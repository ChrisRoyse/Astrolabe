use astrolabe_domain::{
    ASTRO_ANCHOR_CONFIDENCE_RANGE, ASTRO_PANEL_VERSION_ZERO, ASTRO_SOURCE_DRIFT,
    ASTRO_SYMBOL_IDENTITY_EMPTY, ASTRO_SYMBOL_NON_FINITE, AnchorEvidence, SeriesId, SymbolLabel,
    SymbolRecord, canonical_input_bytes, cx_id, frame, series_id,
};
use proptest::prelude::*;
use proptest::test_runner::Config as ProptestConfig;

const PANEL_VERSION: u32 = 7;

fn fixture_symbol() -> SymbolRecord {
    SymbolRecord::new(
        "demo",
        "demo.math.add",
        SymbolLabel::Function.as_str(),
        "src/math.c",
        "c",
        b"int add(int a, int b) { return a + b; }\n".to_vec(),
        "int add(int a, int b)",
        10,
        12,
    )
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

fn symbol_strategy() -> impl Strategy<Value = SymbolRecord> {
    (
        "[A-Za-z0-9_.:/-]{1,12}",
        "[A-Za-z0-9_.:/-]{1,24}",
        "[A-Za-z0-9_.:/-]{1,12}",
        "[A-Za-z0-9_.:/-]{1,24}",
        "[A-Za-z0-9_.:/-]{1,12}",
        proptest::collection::vec(any::<u8>(), 0..64),
        "[A-Za-z0-9_.:/-]{0,32}",
        1_u32..1_000,
        1_u32..1_000,
    )
        .prop_map(
            |(project, qn, label, path, language, snippet, signature, start_line, end_line)| {
                SymbolRecord::new(
                    project, qn, label, path, language, snippet, signature, start_line, end_line,
                )
            },
        )
}

#[test]
fn golden_symbol_identity_is_byte_exact() {
    let symbol = fixture_symbol();
    let canonical = canonical_input_bytes(&symbol).expect("canonical bytes");

    assert_eq!(
        hex_lower(&canonical),
        "000000000000000f617374726f2d73796d626f6c2d7631000000000000000464656d6f000000000000000d64656d6f2e6d6174682e616464000000000000000846756e6374696f6e000000000000000a7372632f6d6174682e630000000000000001630000000000000028696e742061646428696e7420612c20696e74206229207b2072657475726e2061202b20623b207d0a0000000000000015696e742061646428696e7420612c20696e7420622900000000000000040000000a00000000000000040000000c"
    );
    assert_eq!(
        series_id(&symbol).expect("series id").to_string(),
        "67c3e74d1d11c279bc148240aeb2d107"
    );
    assert_eq!(
        cx_id(&symbol, PANEL_VERSION).expect("cx id").to_string(),
        "750a19e5f931d838115b83d12e3ed5a8"
    );
}

#[test]
fn refusal_paths_have_exact_codes_and_remediations() {
    let mut empty = fixture_symbol();
    empty.label.clear();
    let err = canonical_input_bytes(&empty).expect_err("empty label refused");
    assert_eq!(err.code(), ASTRO_SYMBOL_IDENTITY_EMPTY);
    assert_eq!(
        err.remediation(),
        "Populate project, qualified_name, and label before deriving Astrolabe identity."
    );

    let mut non_finite = fixture_symbol();
    non_finite
        .scalars
        .insert("body_tokens".to_string(), f64::INFINITY);
    let err = canonical_input_bytes(&non_finite).expect_err("infinity refused");
    assert_eq!(err.code(), ASTRO_SYMBOL_NON_FINITE);
    assert_eq!(
        err.remediation(),
        "Drop or repair non-finite scalar values before admitting the symbol."
    );

    let mut drift = fixture_symbol();
    drift.expected_source_snippet_blake3 = Some([0; 32]);
    let err = canonical_input_bytes(&drift).expect_err("source drift refused");
    assert_eq!(err.code(), ASTRO_SOURCE_DRIFT);
    assert_eq!(
        err.remediation(),
        "Re-read the source snippet from persisted bytes and recompute the supplied hash before ingest."
    );

    let err = cx_id(&fixture_symbol(), 0).expect_err("zero panel version refused");
    assert_eq!(err.code(), ASTRO_PANEL_VERSION_ZERO);
    assert_eq!(
        err.remediation(),
        "Commission a non-zero panel version before deriving a CxId."
    );

    let mut bad_anchor = fixture_symbol();
    bad_anchor
        .anchors
        .push(AnchorEvidence::new("trace:runtime", 1.01));
    let err = canonical_input_bytes(&bad_anchor).expect_err("bad anchor refused");
    assert_eq!(err.code(), ASTRO_ANCHOR_CONFIDENCE_RANGE);
    assert_eq!(
        err.remediation(),
        "Clamp or reject anchor confidence so only values in (0, 1] are admitted."
    );
}

#[test]
fn moved_identical_function_changes_version_not_series() {
    let mut moved = fixture_symbol();
    moved.start_line += 4;
    moved.end_line += 4;

    assert_ne!(
        cx_id(&fixture_symbol(), PANEL_VERSION).expect("original cx id"),
        cx_id(&moved, PANEL_VERSION).expect("moved cx id")
    );
    assert_eq!(
        series_id(&fixture_symbol()).expect("original series"),
        series_id(&moved).expect("moved series")
    );
}

#[test]
fn any_single_canonical_field_change_changes_cx_id() {
    let base = fixture_symbol();
    let base_id = cx_id(&base, PANEL_VERSION).expect("base cx id");

    let mut changes: Vec<(&str, SymbolRecord)> = Vec::new();
    let mut changed = base.clone();
    changed.project.push_str("-next");
    changes.push(("project", changed));

    let mut changed = base.clone();
    changed.qualified_name.push_str(".next");
    changes.push(("qualified_name", changed));

    let mut changed = base.clone();
    changed.label = SymbolLabel::Method.as_str().to_string();
    changes.push(("label", changed));

    let mut changed = base.clone();
    changed.rel_file_path = "src/math_next.c".to_string();
    changes.push(("rel_file_path", changed));

    let mut changed = base.clone();
    changed.language = "cpp".to_string();
    changes.push(("language", changed));

    let mut changed = base.clone();
    changed.source_snippet_bytes.push(b' ');
    changes.push(("source_snippet_bytes", changed));

    let mut changed = base.clone();
    changed.signature.push_str(" noexcept");
    changes.push(("signature", changed));

    let mut changed = base.clone();
    changed.start_line += 1;
    changes.push(("start_line", changed));

    let mut changed = base.clone();
    changed.end_line += 1;
    changes.push(("end_line", changed));

    for (field, changed) in changes {
        assert_ne!(
            base_id,
            cx_id(&changed, PANEL_VERSION).unwrap_or_else(|err| {
                panic!("{field} mutation should still derive a valid CxId: {err}")
            }),
            "{field} mutation must change CxId"
        );
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn same_inputs_produce_same_cx_id(
        project in "[A-Za-z0-9_.:/-]{1,12}",
        qn in "[A-Za-z0-9_.:/-]{1,24}",
        label in "[A-Za-z0-9_.:/-]{1,12}",
    ) {
        let mut symbol = fixture_symbol();
        symbol.project = project;
        symbol.qualified_name = qn;
        symbol.label = label;

        prop_assert_eq!(
            cx_id(&symbol, PANEL_VERSION).expect("first cx id"),
            cx_id(&symbol, PANEL_VERSION).expect("second cx id")
        );
    }

    #[test]
    fn frame_encoding_is_injective_over_adversarial_bytes(
        a in proptest::collection::vec(any::<u8>(), 0..32),
        b in proptest::collection::vec(any::<u8>(), 0..32),
        c in proptest::collection::vec(any::<u8>(), 0..32),
        d in proptest::collection::vec(any::<u8>(), 0..32),
    ) {
        prop_assume!((a.as_slice(), b.as_slice()) != (c.as_slice(), d.as_slice()));

        let mut left = frame(&a);
        left.extend_from_slice(&frame(&b));
        let mut right = frame(&c);
        right.extend_from_slice(&frame(&d));

        prop_assert_ne!(left, right);
    }

    #[test]
    fn any_single_generated_canonical_field_change_changes_cx_id(base in symbol_strategy()) {
        let base_id = cx_id(&base, PANEL_VERSION).expect("base cx id");

        let mut changed = base.clone();
        changed.project.push('x');
        prop_assert_ne!(base_id, cx_id(&changed, PANEL_VERSION).expect("project cx id"));

        let mut changed = base.clone();
        changed.qualified_name.push('x');
        prop_assert_ne!(base_id, cx_id(&changed, PANEL_VERSION).expect("qn cx id"));

        let mut changed = base.clone();
        changed.label.push('x');
        prop_assert_ne!(base_id, cx_id(&changed, PANEL_VERSION).expect("label cx id"));

        let mut changed = base.clone();
        changed.rel_file_path.push('x');
        prop_assert_ne!(base_id, cx_id(&changed, PANEL_VERSION).expect("path cx id"));

        let mut changed = base.clone();
        changed.language.push('x');
        prop_assert_ne!(base_id, cx_id(&changed, PANEL_VERSION).expect("language cx id"));

        let mut changed = base.clone();
        changed.source_snippet_bytes.push(0xff);
        prop_assert_ne!(base_id, cx_id(&changed, PANEL_VERSION).expect("snippet cx id"));

        let mut changed = base.clone();
        changed.signature.push('x');
        prop_assert_ne!(base_id, cx_id(&changed, PANEL_VERSION).expect("signature cx id"));

        let mut changed = base.clone();
        changed.start_line += 1;
        prop_assert_ne!(base_id, cx_id(&changed, PANEL_VERSION).expect("start line cx id"));

        let mut changed = base.clone();
        changed.end_line += 1;
        prop_assert_ne!(base_id, cx_id(&changed, PANEL_VERSION).expect("end line cx id"));
    }

    #[test]
    fn moved_generated_symbol_changes_version_not_series(mut moved in symbol_strategy(), delta in 1_u32..1_000) {
        let original = moved.clone();
        moved.start_line += delta;
        moved.end_line += delta;

        prop_assert_ne!(
            cx_id(&original, PANEL_VERSION).expect("original cx id"),
            cx_id(&moved, PANEL_VERSION).expect("moved cx id")
        );
        prop_assert_eq!(
            series_id(&original).expect("original series"),
            series_id(&moved).expect("moved series")
        );
    }

    #[test]
    fn series_id_display_roundtrips(bytes in any::<[u8; 16]>()) {
        let id = SeriesId::from_bytes(bytes);
        prop_assert_eq!(id.to_string().parse::<SeriesId>().expect("parse series id"), id);
    }
}
