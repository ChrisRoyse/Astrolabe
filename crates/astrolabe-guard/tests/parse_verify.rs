//! Parse verification for the guard calibration corpus (P7.1 DoD).
//!
//! Every mutation operator must produce syntactically valid but semantically
//! altered code, and every curated vulnerability snippet must be a parseable
//! definition. We verify "syntactically valid" with the real tree-sitter
//! grammars (zero ERROR nodes) and "semantically altered" by asserting the
//! mutant differs from its parent. These grammars are dev-dependencies only;
//! nothing shipped in the binary links them.

use astrolabe_guard::calibration::{
    CalibrationLanguage, MutationOperator, VULNERABILITY_PATTERNS, enumerate_mutants,
    vulnerability_patterns_for,
};
use tree_sitter::{Language, Parser};

fn language(lang: CalibrationLanguage) -> Language {
    match lang {
        CalibrationLanguage::Rust => tree_sitter_rust::LANGUAGE.into(),
        CalibrationLanguage::Python => tree_sitter_python::LANGUAGE.into(),
        CalibrationLanguage::JavaScript => tree_sitter_javascript::LANGUAGE.into(),
        CalibrationLanguage::TypeScript => tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into(),
        CalibrationLanguage::Go => tree_sitter_go::LANGUAGE.into(),
        CalibrationLanguage::Java => tree_sitter_java::LANGUAGE.into(),
        CalibrationLanguage::C => tree_sitter_c::LANGUAGE.into(),
        CalibrationLanguage::Cpp => tree_sitter_cpp::LANGUAGE.into(),
        CalibrationLanguage::CSharp => tree_sitter_c_sharp::LANGUAGE.into(),
        CalibrationLanguage::Ruby => tree_sitter_ruby::LANGUAGE.into(),
    }
}

fn parses_clean(lang: CalibrationLanguage, source: &str) -> bool {
    let mut parser = Parser::new();
    parser.set_language(&language(lang)).expect("load grammar");
    let tree = parser.parse(source, None).expect("parse produced a tree");
    !tree.root_node().has_error()
}

/// One representative, grammar-valid symbol per language that exercises every
/// mutation operator family (comparison, arithmetic, connective, integer
/// literal, negation).
fn mutation_fixture(lang: CalibrationLanguage) -> &'static str {
    match lang {
        CalibrationLanguage::Rust => {
            "fn f(a: i32, b: i32) -> i32 {\n    if a < b && !(a == 0) {\n        return a + 1;\n    }\n    a - b\n}\n"
        }
        CalibrationLanguage::Python => {
            "def f(a, b):\n    if a < b and not (a == 0):\n        return a + 1\n    return a - b\n"
        }
        CalibrationLanguage::JavaScript => {
            "function f(a, b) {\n  if (a < b && !(a == 0)) {\n    return a + 1;\n  }\n  return a - b;\n}\n"
        }
        CalibrationLanguage::TypeScript => {
            "function f(a: number, b: number): number {\n  if (a < b && !(a == 0)) {\n    return a + 1;\n  }\n  return a - b;\n}\n"
        }
        CalibrationLanguage::Go => {
            "func f(a int, b int) int {\n\tif a < b && !(a == 0) {\n\t\treturn a + 1\n\t}\n\treturn a - b\n}\n"
        }
        CalibrationLanguage::Java => {
            "int f(int a, int b) {\n    if (a < b && !(a == 0)) {\n        return a + 1;\n    }\n    return a - b;\n}\n"
        }
        CalibrationLanguage::C => {
            "int f(int a, int b) {\n    if (a < b && !(a == 0)) {\n        return a + 1;\n    }\n    return a - b;\n}\n"
        }
        CalibrationLanguage::Cpp => {
            "int f(int a, int b) {\n    if (a < b && !(a == 0)) {\n        return a + 1;\n    }\n    return a - b;\n}\n"
        }
        CalibrationLanguage::CSharp => {
            "int F(int a, int b) {\n    if (a < b && !(a == 0)) {\n        return a + 1;\n    }\n    return a - b;\n}\n"
        }
        CalibrationLanguage::Ruby => {
            "def f(a, b)\n  if a < b and not (a == 0)\n    return a + 1\n  end\n  a - b\nend\n"
        }
    }
}

#[test]
fn mutants_are_syntactically_valid_and_semantically_altered() {
    for lang in CalibrationLanguage::ALL {
        let parent = mutation_fixture(lang);
        assert!(
            parses_clean(lang, parent),
            "fixture for {} does not parse clean",
            lang.as_str()
        );
        let mutants = enumerate_mutants(parent, lang);
        assert!(
            !mutants.is_empty(),
            "no mutants produced for {}",
            lang.as_str()
        );

        let mut seen_operators = std::collections::BTreeSet::new();
        for mutant in &mutants {
            // Semantically altered: differs from the parent.
            assert_ne!(
                mutant.code,
                parent,
                "{} mutant identical to parent ({:?})",
                lang.as_str(),
                mutant.operator
            );
            // Syntactically valid: zero ERROR nodes.
            assert!(
                parses_clean(lang, &mutant.code),
                "{} mutant via {:?} does not parse clean:\n{}",
                lang.as_str(),
                mutant.operator,
                mutant.code
            );
            seen_operators.insert(mutant.operator);
        }

        // Each fixture exercises at least comparison, arithmetic, connective,
        // off-by-one, and guard removal.
        for op in [
            MutationOperator::ComparisonFlip,
            MutationOperator::ArithmeticSwap,
            MutationOperator::ConnectiveSwap,
            MutationOperator::OffByOne,
            MutationOperator::GuardRemoval,
        ] {
            assert!(
                seen_operators.contains(&op),
                "{} fixture did not exercise {:?}; got {:?}",
                lang.as_str(),
                op,
                seen_operators
            );
        }
    }
}

#[test]
fn every_vulnerability_pattern_parses_clean() {
    for pattern in VULNERABILITY_PATTERNS {
        assert!(
            parses_clean(pattern.language, pattern.code),
            "vulnerability pattern {} ({}) does not parse clean:\n{}",
            pattern.id,
            pattern.language.as_str(),
            pattern.code
        );
    }
    // And every language carries a full catalog.
    for lang in CalibrationLanguage::ALL {
        assert!(
            vulnerability_patterns_for(lang).len() >= 3,
            "{} has fewer than 3 vulnerability patterns",
            lang.as_str()
        );
    }
}
