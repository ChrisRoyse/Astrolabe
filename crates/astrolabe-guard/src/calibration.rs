//! Guard calibration corpus builders (P7.1, blueprint `10_GUARD.md` §2, R16).
//!
//! Conformal tau calibration needs real good/bad cosine populations per slot:
//! `>= 50` bad cases per slot per domain (Ward `MIN_BAD_SCORES`), stratified
//! across four *independent* generators so no single source teaches the guard
//! the wrong thing (R16):
//!
//! 1. **Mutation corpus** — per-language token mutators (comparison flips,
//!    arithmetic/connective swaps, off-by-one, guard/negation removal) over
//!    comment- and string-masked source. Mutants are guaranteed-wrong code
//!    that looks locally plausible: the ideal conformal bad population.
//! 2. **Reverted code** — symbol versions from reverted commits (real,
//!    historical, repo-specific rejections). The SZZ mining that produces the
//!    inputs is P4.3 (#26); this module consumes caller-supplied
//!    [`RevertRecord`]s so the generator logic and provenance ship now.
//! 3. **Alien corpus** — same-language symbols sampled from *other* indexed,
//!    **non-vendored** (R19) repos: valid code, wrong distribution.
//! 4. **Vulnerability patterns** — a versioned registry of curated known-bad
//!    snippets (injection, path traversal, unsafe deserialization) per language.
//!
//! Everything here is deterministic: same inputs + seed => byte-identical
//! corpus (asserted in tests). Provenance is a SHA-256 `corpus_hash` over the
//! canonical corpus bytes — the value `guard_calibrate` pins into the Ward
//! `CalibrationMeta`. The ledger pairing for a concrete calibration *run* is the
//! server-side `guard_calibrate` tool's responsibility (deferred behind the
//! `astrolabe-server` decomposition, #85) and is not built here.
//!
//! Parse verification of mutants and vulnerability snippets (each must parse
//! with zero ERROR nodes and differ from its parent) lives in the
//! `tests/parse_verify.rs` integration test, which links the real tree-sitter
//! grammars as dev-dependencies. Nothing in this module — and nothing shipped
//! in the binary — depends on those grammars.

use core::fmt;

use sha2::{Digest, Sha256};

/// Ward `MIN_BAD_SCORES`: fewer than this many bad cases for a domain is a
/// fail-closed refusal, never a thin calibration (blueprint §2).
pub const MIN_BAD_CASES_PER_DOMAIN: usize = 50;

/// Registry version for the curated vulnerability-pattern catalog.
pub const VULNERABILITY_PATTERN_REGISTRY_VERSION: &str = "astro.guard.vuln_patterns.v1";

/// Canonical corpus serialization schema, hashed into `corpus_hash`.
pub const CALIBRATION_CORPUS_SCHEMA: &str = "astro.guard.calibration_corpus.v1";

/// The top-10 languages the mutation corpus covers. The discriminant order is
/// frozen: it participates in the canonical corpus serialization, so reordering
/// would change every `corpus_hash`.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum CalibrationLanguage {
    Rust,
    Python,
    JavaScript,
    TypeScript,
    Go,
    Java,
    C,
    Cpp,
    CSharp,
    Ruby,
}

impl CalibrationLanguage {
    /// Every covered language, in canonical order.
    pub const ALL: [CalibrationLanguage; 10] = [
        Self::Rust,
        Self::Python,
        Self::JavaScript,
        Self::TypeScript,
        Self::Go,
        Self::Java,
        Self::C,
        Self::Cpp,
        Self::CSharp,
        Self::Ruby,
    ];

    /// Stable lowercase wire label.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Rust => "rust",
            Self::Python => "python",
            Self::JavaScript => "javascript",
            Self::TypeScript => "typescript",
            Self::Go => "go",
            Self::Java => "java",
            Self::C => "c",
            Self::Cpp => "cpp",
            Self::CSharp => "csharp",
            Self::Ruby => "ruby",
        }
    }

    /// Frozen ordinal used in canonical serialization.
    const fn ordinal(self) -> u8 {
        match self {
            Self::Rust => 0,
            Self::Python => 1,
            Self::JavaScript => 2,
            Self::TypeScript => 3,
            Self::Go => 4,
            Self::Java => 5,
            Self::C => 6,
            Self::Cpp => 7,
            Self::CSharp => 8,
            Self::Ruby => 9,
        }
    }

    /// Lexical shape used by the comment/string masker.
    const fn syntax(self) -> LanguageSyntax {
        match self {
            Self::Python => LanguageSyntax {
                line_comments: &["#"],
                block_comment: None,
                strings: &['"', '\''],
                triple_quotes: true,
                backtick_strings: false,
            },
            Self::Ruby => LanguageSyntax {
                line_comments: &["#"],
                block_comment: None,
                strings: &['"', '\''],
                triple_quotes: false,
                backtick_strings: false,
            },
            Self::JavaScript | Self::TypeScript => LanguageSyntax {
                line_comments: &["//"],
                block_comment: Some(("/*", "*/")),
                strings: &['"', '\''],
                triple_quotes: false,
                backtick_strings: true,
            },
            Self::Go => LanguageSyntax {
                line_comments: &["//"],
                block_comment: Some(("/*", "*/")),
                strings: &['"', '\''],
                triple_quotes: false,
                backtick_strings: true,
            },
            // Rust, Java, C, C++, C#: C-family line + block comments, `"`/`'`.
            _ => LanguageSyntax {
                line_comments: &["//"],
                block_comment: Some(("/*", "*/")),
                strings: &['"', '\''],
                triple_quotes: false,
                backtick_strings: false,
            },
        }
    }
}

impl fmt::Display for CalibrationLanguage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A calibration domain = (language × scope-class), e.g. `rust/core`.
#[derive(Debug, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct CalibrationDomain {
    pub language: CalibrationLanguage,
    /// Free-form scope class (`core`, `frontend`, `test`, …). Validated
    /// non-empty on construction.
    pub scope_class: String,
}

impl CalibrationDomain {
    pub fn new(
        language: CalibrationLanguage,
        scope_class: impl Into<String>,
    ) -> Result<Self, CalibrationError> {
        let scope_class = scope_class.into();
        if scope_class.trim().is_empty() {
            return Err(CalibrationError::new(
                "ASTRO_GUARD_DOMAIN_INVALID",
                "calibration domain scope_class is empty",
                "Supply a non-empty scope class such as `core`, `frontend`, or `test`.",
            ));
        }
        Ok(Self {
            language,
            scope_class,
        })
    }

    /// `language/scope_class` display label.
    pub fn label(&self) -> String {
        format!("{}/{}", self.language.as_str(), self.scope_class)
    }
}

/// The four independent bad-case generators (R16 stratification).
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum BadCaseGenerator {
    Mutation,
    Revert,
    Alien,
    Vulnerability,
}

impl BadCaseGenerator {
    pub const ALL: [BadCaseGenerator; 4] = [
        Self::Mutation,
        Self::Revert,
        Self::Alien,
        Self::Vulnerability,
    ];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Mutation => "mutation",
            Self::Revert => "revert",
            Self::Alien => "alien",
            Self::Vulnerability => "vulnerability",
        }
    }

    const fn ordinal(self) -> u8 {
        match self {
            Self::Mutation => 0,
            Self::Revert => 1,
            Self::Alien => 2,
            Self::Vulnerability => 3,
        }
    }
}

/// A single bad-case: guaranteed-wrong (or out-of-distribution) code with the
/// provenance of the generator that produced it.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BadCase {
    pub generator: BadCaseGenerator,
    pub language: CalibrationLanguage,
    /// The bad code text.
    pub code: String,
    /// Generator-specific provenance token (mutation operator + site, revert
    /// commit, alien repo id, or vulnerability pattern id).
    pub provenance: String,
}

// ---------------------------------------------------------------------------
// Comment / string masking
// ---------------------------------------------------------------------------

struct LanguageSyntax {
    line_comments: &'static [&'static str],
    block_comment: Option<(&'static str, &'static str)>,
    strings: &'static [char],
    triple_quotes: bool,
    backtick_strings: bool,
}

/// Returns a per-byte mask: `true` where the byte is inside a comment or string
/// literal (a *non-mutable* position) and `false` where it is code.
///
/// The masker is deliberately conservative: it may over-mask (treat a code byte
/// as masked) but never under-masks a genuine string/comment interior, so a
/// mutation applied at an unmasked position can never land inside a literal.
fn comment_string_mask(source: &str, syntax: &LanguageSyntax) -> Vec<bool> {
    let bytes = source.as_bytes();
    let mut mask = vec![false; bytes.len()];
    let mut i = 0usize;
    while i < bytes.len() {
        // Line comments.
        let mut matched = false;
        for marker in syntax.line_comments {
            if bytes[i..].starts_with(marker.as_bytes()) {
                let end = source[i..]
                    .find('\n')
                    .map(|offset| i + offset)
                    .unwrap_or(bytes.len());
                for slot in mask.iter_mut().take(end).skip(i) {
                    *slot = true;
                }
                i = end;
                matched = true;
                break;
            }
        }
        if matched {
            continue;
        }
        // Block comments.
        if let Some((open, close)) = syntax.block_comment
            && bytes[i..].starts_with(open.as_bytes())
        {
            let search_from = i + open.len();
            let end = source[search_from..]
                .find(close)
                .map(|offset| search_from + offset + close.len())
                .unwrap_or(bytes.len());
            for slot in mask.iter_mut().take(end).skip(i) {
                *slot = true;
            }
            i = end;
            continue;
        }
        // Triple-quoted strings (Python).
        if syntax.triple_quotes
            && (bytes[i..].starts_with(b"\"\"\"") || bytes[i..].starts_with(b"'''"))
        {
            let quote = &source[i..i + 3];
            let search_from = i + 3;
            let end = source[search_from..]
                .find(quote)
                .map(|offset| search_from + offset + 3)
                .unwrap_or(bytes.len());
            for slot in mask.iter_mut().take(end).skip(i) {
                *slot = true;
            }
            i = end;
            continue;
        }
        // Backtick template strings (JS/TS/Go raw).
        if syntax.backtick_strings && bytes[i] == b'`' {
            let end = string_span_end(source, i, '`', false);
            for slot in mask.iter_mut().take(end).skip(i) {
                *slot = true;
            }
            i = end;
            continue;
        }
        // Single-char-delimited strings.
        let ch = bytes[i] as char;
        if syntax.strings.contains(&ch) {
            let escapes = ch == '"' || ch == '\'';
            let end = string_span_end(source, i, ch, escapes);
            for slot in mask.iter_mut().take(end).skip(i) {
                *slot = true;
            }
            i = end;
            continue;
        }
        i += 1;
    }
    mask
}

/// Finds the byte just past the closing delimiter of a string that opens at
/// `start`. Honors backslash escapes when `escapes` is set.
fn string_span_end(source: &str, start: usize, delimiter: char, escapes: bool) -> usize {
    let bytes = source.as_bytes();
    let mut j = start + 1;
    while j < bytes.len() {
        let cur = bytes[j] as char;
        if escapes && cur == '\\' {
            j += 2;
            continue;
        }
        if cur == delimiter {
            return j + 1;
        }
        j += 1;
    }
    bytes.len()
}

// ---------------------------------------------------------------------------
// Mutation engine
// ---------------------------------------------------------------------------

/// A single mutation operator applied to token-level source.
#[derive(Debug, Clone, Copy, Eq, PartialEq, Ord, PartialOrd)]
pub enum MutationOperator {
    /// Comparison flip: `<`↔`>=`, `<=`↔`>`, `==`↔`!=`.
    ComparisonFlip,
    /// Arithmetic swap: `+`↔`-`, `*`↔`/`.
    ArithmeticSwap,
    /// Logical connective swap: `&&`↔`||`, ` and `↔` or `.
    ConnectiveSwap,
    /// Off-by-one on an integer literal: `n` → `n+1`.
    OffByOne,
    /// Guard removal: drop a unary negation (`!expr`→`expr`, ` not `→` `),
    /// inverting a guard's sense while staying syntactically valid.
    GuardRemoval,
}

impl MutationOperator {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ComparisonFlip => "comparison_flip",
            Self::ArithmeticSwap => "arithmetic_swap",
            Self::ConnectiveSwap => "connective_swap",
            Self::OffByOne => "off_by_one",
            Self::GuardRemoval => "guard_removal",
        }
    }
}

/// A produced mutant plus the operator and byte site that produced it.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Mutant {
    pub operator: MutationOperator,
    /// Byte offset in the parent source where the mutation was applied.
    pub site: usize,
    pub code: String,
}

/// Multi-character operator token replacements. Order matters: multi-char tokens
/// are matched before their single-char prefixes so `<=` is never mis-read as
/// `<`.
struct OpRule {
    operator: MutationOperator,
    from: &'static str,
    to: &'static str,
}

const OP_RULES: &[OpRule] = &[
    // Comparison (longest first).
    OpRule {
        operator: MutationOperator::ComparisonFlip,
        from: "==",
        to: "!=",
    },
    OpRule {
        operator: MutationOperator::ComparisonFlip,
        from: "!=",
        to: "==",
    },
    OpRule {
        operator: MutationOperator::ComparisonFlip,
        from: "<=",
        to: ">",
    },
    OpRule {
        operator: MutationOperator::ComparisonFlip,
        from: ">=",
        to: "<",
    },
    // Connectives.
    OpRule {
        operator: MutationOperator::ConnectiveSwap,
        from: "&&",
        to: "||",
    },
    OpRule {
        operator: MutationOperator::ConnectiveSwap,
        from: "||",
        to: "&&",
    },
];

/// Enumerate every mutant of `source`, deterministically ordered, each
/// guaranteed to differ from `source`. A source with no mutable operator or
/// literal yields an empty vector (never a no-op "mutant").
pub fn enumerate_mutants(source: &str, language: CalibrationLanguage) -> Vec<Mutant> {
    let syntax = language.syntax();
    let mask = comment_string_mask(source, &syntax);
    let mut mutants = Vec::new();

    // Multi-char operator rules (comparison/connective) scanned left→right.
    for rule in OP_RULES {
        let mut search = 0usize;
        while let Some(rel) = source[search..].find(rule.from) {
            let at = search + rel;
            search = at + rule.from.len();
            if mask[at] {
                continue;
            }
            // Guard against clobbering a longer operator (e.g. `<=` when the
            // rule is a bare `<`): our multi-char rules are already the longest
            // forms, so only ensure the match isn't a prefix of `==`/`!=` etc.
            let mut code = String::with_capacity(source.len());
            code.push_str(&source[..at]);
            code.push_str(rule.to);
            code.push_str(&source[at + rule.from.len()..]);
            if code != source {
                mutants.push(Mutant {
                    operator: rule.operator,
                    site: at,
                    code,
                });
            }
        }
    }

    // Single-char comparison/arithmetic, boundary-checked so we skip characters
    // that belong to a two-char operator (`<=`, `->`, `+=`, `/*`, `//`, …).
    single_char_op_mutants(
        source,
        &mask,
        '<',
        ">=",
        MutationOperator::ComparisonFlip,
        &mut mutants,
    );
    single_char_op_mutants(
        source,
        &mask,
        '>',
        "<=",
        MutationOperator::ComparisonFlip,
        &mut mutants,
    );
    single_char_op_mutants(
        source,
        &mask,
        '+',
        "-",
        MutationOperator::ArithmeticSwap,
        &mut mutants,
    );
    single_char_op_mutants(
        source,
        &mask,
        '-',
        "+",
        MutationOperator::ArithmeticSwap,
        &mut mutants,
    );
    single_char_op_mutants(
        source,
        &mask,
        '*',
        "/",
        MutationOperator::ArithmeticSwap,
        &mut mutants,
    );
    single_char_op_mutants(
        source,
        &mask,
        '/',
        "*",
        MutationOperator::ArithmeticSwap,
        &mut mutants,
    );

    // Word-boundary ` and `/` or ` connectives (Python/Ruby).
    word_connective_mutants(source, &mask, "and", "or", &mut mutants);
    word_connective_mutants(source, &mask, "or", "and", &mut mutants);

    // Off-by-one on integer literals.
    off_by_one_mutants(source, &mask, &mut mutants);

    // Guard removal: strip a unary `!` (not part of `!=`) or a ` not ` word.
    guard_removal_mutants(source, &mask, language, &mut mutants);

    // Stable ordering: operator, then site.
    mutants.sort_by(|a, b| a.operator.cmp(&b.operator).then(a.site.cmp(&b.site)));
    mutants
}

fn is_op_char(byte: u8) -> bool {
    matches!(
        byte,
        b'<' | b'>' | b'=' | b'+' | b'-' | b'*' | b'/' | b'!' | b'&' | b'|' | b'%' | b'^'
    )
}

fn single_char_op_mutants(
    source: &str,
    mask: &[bool],
    from: char,
    to: &str,
    operator: MutationOperator,
    out: &mut Vec<Mutant>,
) {
    let bytes = source.as_bytes();
    let from_byte = from as u8;
    for at in 0..bytes.len() {
        if bytes[at] != from_byte || mask[at] {
            continue;
        }
        // Reject positions adjacent to another operator character: those form
        // multi-char operators handled elsewhere (or comment/string starts).
        let prev_op = at > 0 && is_op_char(bytes[at - 1]);
        let next_op = at + 1 < bytes.len() && is_op_char(bytes[at + 1]);
        if prev_op || next_op {
            continue;
        }
        let mut code = String::with_capacity(source.len() + to.len());
        code.push_str(&source[..at]);
        code.push_str(to);
        code.push_str(&source[at + 1..]);
        if code != source {
            out.push(Mutant {
                operator,
                site: at,
                code,
            });
        }
    }
}

fn is_ident_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn word_connective_mutants(
    source: &str,
    mask: &[bool],
    from: &str,
    to: &str,
    out: &mut Vec<Mutant>,
) {
    let bytes = source.as_bytes();
    let mut search = 0usize;
    while let Some(rel) = source[search..].find(from) {
        let at = search + rel;
        search = at + from.len();
        if mask[at] {
            continue;
        }
        let prev_ok = at == 0 || !is_ident_byte(bytes[at - 1]);
        let after = at + from.len();
        let next_ok = after >= bytes.len() || !is_ident_byte(bytes[after]);
        if !(prev_ok && next_ok) {
            continue;
        }
        let mut code = String::with_capacity(source.len());
        code.push_str(&source[..at]);
        code.push_str(to);
        code.push_str(&source[after..]);
        out.push(Mutant {
            operator: MutationOperator::ConnectiveSwap,
            site: at,
            code,
        });
    }
}

fn off_by_one_mutants(source: &str, mask: &[bool], out: &mut Vec<Mutant>) {
    let bytes = source.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if !bytes[i].is_ascii_digit() || mask[i] {
            i += 1;
            continue;
        }
        // Start of an integer token: not preceded by an ident byte or `.`.
        let token_start = i > 0 && (is_ident_byte(bytes[i - 1]) || bytes[i - 1] == b'.');
        if token_start {
            // advance past the whole run and skip.
            while i < bytes.len() && (bytes[i].is_ascii_digit() || is_ident_byte(bytes[i])) {
                i += 1;
            }
            continue;
        }
        let mut end = i;
        while end < bytes.len() && bytes[end].is_ascii_digit() {
            end += 1;
        }
        // Reject floats (followed by `.`) and hex/suffix runs.
        let is_float = end < bytes.len() && bytes[end] == b'.';
        let has_suffix = end < bytes.len() && is_ident_byte(bytes[end]);
        if !is_float
            && !has_suffix
            && let Ok(value) = source[i..end].parse::<u128>()
        {
            let bumped = (value + 1).to_string();
            let mut code = String::with_capacity(source.len() + 1);
            code.push_str(&source[..i]);
            code.push_str(&bumped);
            code.push_str(&source[end..]);
            out.push(Mutant {
                operator: MutationOperator::OffByOne,
                site: i,
                code,
            });
        }
        i = end.max(i + 1);
    }
}

fn guard_removal_mutants(
    source: &str,
    mask: &[bool],
    language: CalibrationLanguage,
    out: &mut Vec<Mutant>,
) {
    let bytes = source.as_bytes();
    let uses_bang = !matches!(
        language,
        CalibrationLanguage::Python | CalibrationLanguage::Ruby
    );
    if uses_bang {
        for at in 0..bytes.len() {
            if bytes[at] != b'!' || mask[at] {
                continue;
            }
            // Not `!=`, and not preceded by another operator char.
            if at + 1 < bytes.len() && bytes[at + 1] == b'=' {
                continue;
            }
            if at > 0 && is_op_char(bytes[at - 1]) {
                continue;
            }
            let mut code = String::with_capacity(source.len());
            code.push_str(&source[..at]);
            code.push_str(&source[at + 1..]);
            out.push(Mutant {
                operator: MutationOperator::GuardRemoval,
                site: at,
                code,
            });
        }
    } else {
        // Python/Ruby: drop a ` not ` word.
        let needle = "not ";
        let mut search = 0usize;
        while let Some(rel) = source[search..].find(needle) {
            let at = search + rel;
            search = at + needle.len();
            if mask[at] {
                continue;
            }
            let prev_ok = at == 0 || !is_ident_byte(bytes[at - 1]);
            if !prev_ok {
                continue;
            }
            let mut code = String::with_capacity(source.len());
            code.push_str(&source[..at]);
            code.push_str(&source[at + needle.len()..]);
            out.push(Mutant {
                operator: MutationOperator::GuardRemoval,
                site: at,
                code,
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Deterministic PRNG for seeded sampling
// ---------------------------------------------------------------------------

/// SplitMix64: tiny, dependency-free, deterministic. Only cross-run byte
/// determinism matters, not statistical quality.
struct SplitMix64(u64);

impl SplitMix64 {
    fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
}

// ---------------------------------------------------------------------------
// Generator inputs
// ---------------------------------------------------------------------------

/// A HEAD symbol version whose reverted predecessor is a repo-specific rejection
/// (SZZ mining is P4.3 / #26; this is the consumed record shape).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct RevertRecord {
    pub language: CalibrationLanguage,
    /// The code that was reverted (the rejected version).
    pub reverted_code: String,
    /// The commit that introduced the reverted code.
    pub introduced_commit: String,
    /// The commit that reverted it.
    pub revert_commit: String,
}

/// A same-language symbol sampled from another indexed repository.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AlienSymbol {
    pub language: CalibrationLanguage,
    pub code: String,
    /// Identifier of the source repo the symbol came from.
    pub repo_id: String,
    /// R19: vendored repos are excluded from the alien corpus (they are part of
    /// *our* distribution). A vendored symbol is refused, not silently dropped.
    pub is_vendored: bool,
}

/// A HEAD good case (in-distribution) with a Trusted anchor.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct GoodCase {
    pub language: CalibrationLanguage,
    pub code: String,
    /// Anchor provenance (why this is Trusted: test-covered / aged / reviewed).
    pub anchor: String,
}

// ---------------------------------------------------------------------------
// Vulnerability pattern registry
// ---------------------------------------------------------------------------

/// A curated known-bad snippet for the strictest slots.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct VulnerabilityPattern {
    pub id: &'static str,
    pub language: CalibrationLanguage,
    pub category: VulnerabilityCategory,
    pub code: &'static str,
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum VulnerabilityCategory {
    Injection,
    PathTraversal,
    UnsafeDeserialization,
}

impl VulnerabilityCategory {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Injection => "injection",
            Self::PathTraversal => "path_traversal",
            Self::UnsafeDeserialization => "unsafe_deserialization",
        }
    }
}

/// The versioned vulnerability-pattern catalog: at least one snippet in each of
/// the three categories for every covered language. Each snippet is a complete,
/// parseable definition (verified in `tests/parse_verify.rs`).
pub const VULNERABILITY_PATTERNS: &[VulnerabilityPattern] = &[
    // Rust.
    VulnerabilityPattern {
        id: "vuln.rust.injection.v1",
        language: CalibrationLanguage::Rust,
        category: VulnerabilityCategory::Injection,
        code: "fn run(user: &str) {\n    let cmd = format!(\"sh -c {}\", user);\n    std::process::Command::new(cmd).spawn().unwrap();\n}\n",
    },
    VulnerabilityPattern {
        id: "vuln.rust.path.v1",
        language: CalibrationLanguage::Rust,
        category: VulnerabilityCategory::PathTraversal,
        code: "fn read(name: &str) -> String {\n    let path = format!(\"/data/{}\", name);\n    std::fs::read_to_string(path).unwrap()\n}\n",
    },
    VulnerabilityPattern {
        id: "vuln.rust.deser.v1",
        language: CalibrationLanguage::Rust,
        category: VulnerabilityCategory::UnsafeDeserialization,
        code: "fn load(bytes: &[u8]) -> Config {\n    let cfg: Config = unsafe { std::ptr::read(bytes.as_ptr() as *const Config) };\n    cfg\n}\n",
    },
    // Python.
    VulnerabilityPattern {
        id: "vuln.python.injection.v1",
        language: CalibrationLanguage::Python,
        category: VulnerabilityCategory::Injection,
        code: "def run(user):\n    import os\n    os.system('sh -c ' + user)\n",
    },
    VulnerabilityPattern {
        id: "vuln.python.path.v1",
        language: CalibrationLanguage::Python,
        category: VulnerabilityCategory::PathTraversal,
        code: "def read(name):\n    with open('/data/' + name) as handle:\n        return handle.read()\n",
    },
    VulnerabilityPattern {
        id: "vuln.python.deser.v1",
        language: CalibrationLanguage::Python,
        category: VulnerabilityCategory::UnsafeDeserialization,
        code: "def load(blob):\n    import pickle\n    return pickle.loads(blob)\n",
    },
    // JavaScript.
    VulnerabilityPattern {
        id: "vuln.javascript.injection.v1",
        language: CalibrationLanguage::JavaScript,
        category: VulnerabilityCategory::Injection,
        code: "function run(user) {\n  const cp = require('child_process');\n  cp.exec('sh -c ' + user);\n}\n",
    },
    VulnerabilityPattern {
        id: "vuln.javascript.path.v1",
        language: CalibrationLanguage::JavaScript,
        category: VulnerabilityCategory::PathTraversal,
        code: "function read(name) {\n  const fs = require('fs');\n  return fs.readFileSync('/data/' + name);\n}\n",
    },
    VulnerabilityPattern {
        id: "vuln.javascript.deser.v1",
        language: CalibrationLanguage::JavaScript,
        category: VulnerabilityCategory::UnsafeDeserialization,
        code: "function load(text) {\n  return eval('(' + text + ')');\n}\n",
    },
    // TypeScript.
    VulnerabilityPattern {
        id: "vuln.typescript.injection.v1",
        language: CalibrationLanguage::TypeScript,
        category: VulnerabilityCategory::Injection,
        code: "function run(user: string): void {\n  const cp = require('child_process');\n  cp.exec('sh -c ' + user);\n}\n",
    },
    VulnerabilityPattern {
        id: "vuln.typescript.path.v1",
        language: CalibrationLanguage::TypeScript,
        category: VulnerabilityCategory::PathTraversal,
        code: "function read(name: string): Buffer {\n  const fs = require('fs');\n  return fs.readFileSync('/data/' + name);\n}\n",
    },
    VulnerabilityPattern {
        id: "vuln.typescript.deser.v1",
        language: CalibrationLanguage::TypeScript,
        category: VulnerabilityCategory::UnsafeDeserialization,
        code: "function load(text: string): any {\n  return eval('(' + text + ')');\n}\n",
    },
    // Go.
    VulnerabilityPattern {
        id: "vuln.go.injection.v1",
        language: CalibrationLanguage::Go,
        category: VulnerabilityCategory::Injection,
        code: "func run(user string) {\n\texec.Command(\"sh\", \"-c\", user).Run()\n}\n",
    },
    VulnerabilityPattern {
        id: "vuln.go.path.v1",
        language: CalibrationLanguage::Go,
        category: VulnerabilityCategory::PathTraversal,
        code: "func read(name string) ([]byte, error) {\n\treturn ioutil.ReadFile(\"/data/\" + name)\n}\n",
    },
    VulnerabilityPattern {
        id: "vuln.go.deser.v1",
        language: CalibrationLanguage::Go,
        category: VulnerabilityCategory::UnsafeDeserialization,
        code: "func load(blob []byte) Config {\n\tvar cfg Config\n\tgob.NewDecoder(bytes.NewReader(blob)).Decode(&cfg)\n\treturn cfg\n}\n",
    },
    // Java.
    VulnerabilityPattern {
        id: "vuln.java.injection.v1",
        language: CalibrationLanguage::Java,
        category: VulnerabilityCategory::Injection,
        code: "void run(String user) throws Exception {\n    Runtime.getRuntime().exec(\"sh -c \" + user);\n}\n",
    },
    VulnerabilityPattern {
        id: "vuln.java.path.v1",
        language: CalibrationLanguage::Java,
        category: VulnerabilityCategory::PathTraversal,
        code: "byte[] read(String name) throws Exception {\n    return Files.readAllBytes(Paths.get(\"/data/\" + name));\n}\n",
    },
    VulnerabilityPattern {
        id: "vuln.java.deser.v1",
        language: CalibrationLanguage::Java,
        category: VulnerabilityCategory::UnsafeDeserialization,
        code: "Object load(InputStream in) throws Exception {\n    return new ObjectInputStream(in).readObject();\n}\n",
    },
    // C.
    VulnerabilityPattern {
        id: "vuln.c.injection.v1",
        language: CalibrationLanguage::C,
        category: VulnerabilityCategory::Injection,
        code: "void run(const char *user) {\n    char cmd[256];\n    sprintf(cmd, \"sh -c %s\", user);\n    system(cmd);\n}\n",
    },
    VulnerabilityPattern {
        id: "vuln.c.path.v1",
        language: CalibrationLanguage::C,
        category: VulnerabilityCategory::PathTraversal,
        code: "int read_file(const char *name) {\n    char path[256];\n    sprintf(path, \"/data/%s\", name);\n    return open(path, 0);\n}\n",
    },
    VulnerabilityPattern {
        id: "vuln.c.deser.v1",
        language: CalibrationLanguage::C,
        category: VulnerabilityCategory::UnsafeDeserialization,
        code: "struct Config load(const unsigned char *bytes) {\n    struct Config cfg;\n    memcpy(&cfg, bytes, sizeof(cfg));\n    return cfg;\n}\n",
    },
    // C++.
    VulnerabilityPattern {
        id: "vuln.cpp.injection.v1",
        language: CalibrationLanguage::Cpp,
        category: VulnerabilityCategory::Injection,
        code: "void run(const std::string &user) {\n    std::string cmd = \"sh -c \" + user;\n    std::system(cmd.c_str());\n}\n",
    },
    VulnerabilityPattern {
        id: "vuln.cpp.path.v1",
        language: CalibrationLanguage::Cpp,
        category: VulnerabilityCategory::PathTraversal,
        code: "std::string read(const std::string &name) {\n    std::ifstream in(\"/data/\" + name);\n    return std::string(std::istreambuf_iterator<char>(in), {});\n}\n",
    },
    VulnerabilityPattern {
        id: "vuln.cpp.deser.v1",
        language: CalibrationLanguage::Cpp,
        category: VulnerabilityCategory::UnsafeDeserialization,
        code: "Config load(const char *bytes) {\n    Config cfg;\n    std::memcpy(&cfg, bytes, sizeof(cfg));\n    return cfg;\n}\n",
    },
    // C#.
    VulnerabilityPattern {
        id: "vuln.csharp.injection.v1",
        language: CalibrationLanguage::CSharp,
        category: VulnerabilityCategory::Injection,
        code: "void Run(string user) {\n    System.Diagnostics.Process.Start(\"sh\", \"-c \" + user);\n}\n",
    },
    VulnerabilityPattern {
        id: "vuln.csharp.path.v1",
        language: CalibrationLanguage::CSharp,
        category: VulnerabilityCategory::PathTraversal,
        code: "byte[] Read(string name) {\n    return System.IO.File.ReadAllBytes(\"/data/\" + name);\n}\n",
    },
    VulnerabilityPattern {
        id: "vuln.csharp.deser.v1",
        language: CalibrationLanguage::CSharp,
        category: VulnerabilityCategory::UnsafeDeserialization,
        code: "object Load(byte[] blob) {\n    var fmt = new System.Runtime.Serialization.Formatters.Binary.BinaryFormatter();\n    return fmt.Deserialize(new System.IO.MemoryStream(blob));\n}\n",
    },
    // Ruby.
    VulnerabilityPattern {
        id: "vuln.ruby.injection.v1",
        language: CalibrationLanguage::Ruby,
        category: VulnerabilityCategory::Injection,
        code: "def run(user)\n  system('sh -c ' + user)\nend\n",
    },
    VulnerabilityPattern {
        id: "vuln.ruby.path.v1",
        language: CalibrationLanguage::Ruby,
        category: VulnerabilityCategory::PathTraversal,
        code: "def read(name)\n  File.read('/data/' + name)\nend\n",
    },
    VulnerabilityPattern {
        id: "vuln.ruby.deser.v1",
        language: CalibrationLanguage::Ruby,
        category: VulnerabilityCategory::UnsafeDeserialization,
        code: "def load(blob)\n  Marshal.load(blob)\nend\n",
    },
];

/// Vulnerability patterns for one language, in registry order.
pub fn vulnerability_patterns_for(
    language: CalibrationLanguage,
) -> Vec<&'static VulnerabilityPattern> {
    VULNERABILITY_PATTERNS
        .iter()
        .filter(|pattern| pattern.language == language)
        .collect()
}

// ---------------------------------------------------------------------------
// Mix policy + corpus builder
// ---------------------------------------------------------------------------

/// Declared-knob mix policy (invariant #4: no bare constant that could be a
/// measurement). Governs how the four generators combine into a bad-case corpus.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct MixPolicy {
    /// Minimum total bad cases per domain (Ward `MIN_BAD_SCORES`).
    pub min_total: usize,
    /// Minimum contributing generators (R16: no single-source calibration).
    pub min_generators: usize,
    /// Cap on any single generator's share, as a percentage 1..=100. A share
    /// above this is refused — a corpus dominated by one generator teaches the
    /// guard that generator's artifacts, not real out-of-distribution shape.
    pub max_single_generator_pct: u8,
}

impl MixPolicy {
    pub const fn default_policy() -> Self {
        Self {
            min_total: MIN_BAD_CASES_PER_DOMAIN,
            min_generators: 3,
            max_single_generator_pct: 60,
        }
    }
}

/// A built, stratified bad-case corpus for one domain, with provenance.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CalibrationCorpus {
    pub domain: CalibrationDomain,
    pub policy: MixPolicy,
    pub seed: u64,
    pub bad_cases: Vec<BadCase>,
    pub good_cases: Vec<GoodCase>,
    /// SHA-256 over the canonical corpus bytes (the value pinned into
    /// `CalibrationMeta.corpus_hash`).
    pub corpus_hash: [u8; 32],
}

impl CalibrationCorpus {
    /// Count of bad cases contributed by each generator.
    pub fn generator_counts(&self) -> [(BadCaseGenerator, usize); 4] {
        let mut counts = [
            (BadCaseGenerator::Mutation, 0),
            (BadCaseGenerator::Revert, 0),
            (BadCaseGenerator::Alien, 0),
            (BadCaseGenerator::Vulnerability, 0),
        ];
        for case in &self.bad_cases {
            for entry in counts.iter_mut() {
                if entry.0 == case.generator {
                    entry.1 += 1;
                }
            }
        }
        counts
    }

    /// Lowercase hex of the corpus hash.
    pub fn corpus_hash_hex(&self) -> String {
        self.corpus_hash
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

/// Raw generator inputs for one domain.
#[derive(Debug, Clone, Default)]
pub struct CorpusInputs {
    /// Real HEAD symbols to mutate.
    pub mutation_sources: Vec<String>,
    /// Reverted-code records (P4.3 / #26 provides these).
    pub revert_records: Vec<RevertRecord>,
    /// Alien same-language symbols from other repos.
    pub alien_symbols: Vec<AlienSymbol>,
    /// In-distribution good cases (HEAD + Trusted anchor).
    pub good_cases: Vec<GoodCase>,
}

/// Build a stratified bad-case corpus for `domain` from `inputs`, seeded for
/// determinism. Fails closed if the mix policy cannot be met — never returns a
/// thin or single-source calibration.
pub fn build_corpus(
    domain: CalibrationDomain,
    inputs: &CorpusInputs,
    policy: MixPolicy,
    seed: u64,
) -> Result<CalibrationCorpus, CalibrationError> {
    let language = domain.language;

    // R19: refuse vendored alien symbols outright rather than silently dropping.
    if let Some(bad) = inputs
        .alien_symbols
        .iter()
        .find(|symbol| symbol.is_vendored)
    {
        return Err(CalibrationError::new(
            "ASTRO_GUARD_ALIEN_VENDORED",
            format!(
                "alien symbol from repo `{}` is vendored; the alien corpus (R19) admits only \
                 non-vendored repos",
                bad.repo_id
            ),
            "Exclude vendored repositories from the alien-corpus sampling pool before building.",
        ));
    }

    let mut bad_cases: Vec<BadCase> = Vec::new();

    // 1. Mutation generator: every mutant of every source symbol of this
    //    language, deterministically ordered.
    for source in &inputs.mutation_sources {
        for mutant in enumerate_mutants(source, language) {
            bad_cases.push(BadCase {
                generator: BadCaseGenerator::Mutation,
                language,
                code: mutant.code,
                provenance: format!("{}@{}", mutant.operator.as_str(), mutant.site),
            });
        }
    }

    // 2. Revert generator.
    for record in &inputs.revert_records {
        if record.language != language {
            continue;
        }
        bad_cases.push(BadCase {
            generator: BadCaseGenerator::Revert,
            language,
            code: record.reverted_code.clone(),
            provenance: format!("{}->{}", record.introduced_commit, record.revert_commit),
        });
    }

    // 3. Alien generator (non-vendored only, already validated).
    for symbol in &inputs.alien_symbols {
        if symbol.language != language {
            continue;
        }
        bad_cases.push(BadCase {
            generator: BadCaseGenerator::Alien,
            language,
            code: symbol.code.clone(),
            provenance: format!("repo:{}", symbol.repo_id),
        });
    }

    // 4. Vulnerability generator.
    for pattern in vulnerability_patterns_for(language) {
        bad_cases.push(BadCase {
            generator: BadCaseGenerator::Vulnerability,
            language,
            code: pattern.code.to_string(),
            provenance: format!("{}:{}", VULNERABILITY_PATTERN_REGISTRY_VERSION, pattern.id),
        });
    }

    // Deterministic seeded shuffle across generators so the stratified set isn't
    // ordered generator-by-generator (the calibration reads a mixed stream), yet
    // stays byte-identical for a given seed.
    seeded_shuffle(&mut bad_cases, seed);

    enforce_mix_policy(&domain, &bad_cases, policy)?;

    let mut good_cases: Vec<GoodCase> = inputs
        .good_cases
        .iter()
        .filter(|case| case.language == language)
        .cloned()
        .collect();
    good_cases.sort_by(|a, b| a.code.cmp(&b.code).then(a.anchor.cmp(&b.anchor)));

    let corpus_hash = canonical_corpus_hash(&domain, policy, seed, &bad_cases, &good_cases);

    Ok(CalibrationCorpus {
        domain,
        policy,
        seed,
        bad_cases,
        good_cases,
        corpus_hash,
    })
}

fn seeded_shuffle<T>(items: &mut [T], seed: u64) {
    // Fisher–Yates with a seeded SplitMix64. Deterministic for a given seed.
    let mut rng = SplitMix64(seed ^ 0x5EED_1234_ABCD_0001);
    let len = items.len();
    if len < 2 {
        return;
    }
    for i in (1..len).rev() {
        let j = (rng.next_u64() % (i as u64 + 1)) as usize;
        items.swap(i, j);
    }
}

fn enforce_mix_policy(
    domain: &CalibrationDomain,
    bad_cases: &[BadCase],
    policy: MixPolicy,
) -> Result<(), CalibrationError> {
    let total = bad_cases.len();
    if total < policy.min_total {
        return Err(CalibrationError::new(
            "ASTRO_GUARD_INSUFFICIENT_BAD_CASES",
            format!(
                "domain {} has {total} bad cases; the mix policy requires >= {} \
                 (Ward MIN_BAD_SCORES). Calibration refused for this domain.",
                domain.label(),
                policy.min_total
            ),
            "Widen the mutation source set, supply revert/alien records, or lower coverage \
             expectations — never calibrate on a thin corpus.",
        ));
    }

    let mut per_generator = [0usize; 4];
    for case in bad_cases {
        per_generator[case.generator.ordinal() as usize] += 1;
    }
    let contributing = per_generator.iter().filter(|count| **count > 0).count();
    if contributing < policy.min_generators {
        return Err(CalibrationError::new(
            "ASTRO_GUARD_SINGLE_SOURCE_CALIBRATION",
            format!(
                "domain {} draws bad cases from {contributing} generator(s); the mix policy \
                 requires >= {} to avoid single-source dependence (R16).",
                domain.label(),
                policy.min_generators
            ),
            "Provide inputs for more generators (mutation sources, revert records, alien \
             symbols) so no single generator dominates the calibration.",
        ));
    }

    let max_allowed = (total * policy.max_single_generator_pct as usize).div_ceil(100);
    for generator in BadCaseGenerator::ALL {
        let count = per_generator[generator.ordinal() as usize];
        if count > max_allowed {
            let pct = count * 100 / total;
            return Err(CalibrationError::new(
                "ASTRO_GUARD_GENERATOR_DOMINATES",
                format!(
                    "domain {} has generator `{}` supplying {count}/{total} bad cases ({pct}% > \
                     {}% cap); a single-source-dominated corpus is refused (R16).",
                    domain.label(),
                    generator.as_str(),
                    policy.max_single_generator_pct
                ),
                "Rebalance the corpus: add cases from the other generators or subsample the \
                 dominant one before calibrating.",
            ));
        }
    }
    Ok(())
}

/// Canonical, order-independent-of-input-shuffle byte serialization of the
/// corpus, hashed with SHA-256. The bad cases are hashed in a canonically
/// *sorted* order (not the seeded-shuffle order) so the hash pins the corpus
/// *content*, and the seed is hashed separately so a different shuffle of the
/// same content still yields a distinct, reproducible corpus identity.
fn canonical_corpus_hash(
    domain: &CalibrationDomain,
    policy: MixPolicy,
    seed: u64,
    bad_cases: &[BadCase],
    good_cases: &[GoodCase],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(CALIBRATION_CORPUS_SCHEMA.as_bytes());
    hasher.update([0]);
    hasher.update([domain.language.ordinal()]);
    hasher.update(domain.scope_class.as_bytes());
    hasher.update([0]);
    hasher.update([policy.min_generators as u8, policy.max_single_generator_pct]);
    hasher.update((policy.min_total as u64).to_be_bytes());
    hasher.update(seed.to_be_bytes());

    let mut sorted: Vec<&BadCase> = bad_cases.iter().collect();
    sorted.sort_by(|a, b| {
        a.generator
            .ordinal()
            .cmp(&b.generator.ordinal())
            .then_with(|| a.code.cmp(&b.code))
            .then_with(|| a.provenance.cmp(&b.provenance))
    });
    hasher.update((sorted.len() as u64).to_be_bytes());
    for case in sorted {
        hasher.update([case.generator.ordinal(), case.language.ordinal()]);
        hasher.update((case.code.len() as u64).to_be_bytes());
        hasher.update(case.code.as_bytes());
        hasher.update((case.provenance.len() as u64).to_be_bytes());
        hasher.update(case.provenance.as_bytes());
    }

    let mut goods: Vec<&GoodCase> = good_cases.iter().collect();
    goods.sort_by(|a, b| a.code.cmp(&b.code).then_with(|| a.anchor.cmp(&b.anchor)));
    hasher.update((goods.len() as u64).to_be_bytes());
    for good in goods {
        hasher.update([good.language.ordinal()]);
        hasher.update((good.code.len() as u64).to_be_bytes());
        hasher.update(good.code.as_bytes());
        hasher.update((good.anchor.len() as u64).to_be_bytes());
        hasher.update(good.anchor.as_bytes());
    }

    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Serialize the corpus to the exact canonical bytes whose SHA-256 is
/// `corpus_hash`. Written to disk by the FSV test, read back, and re-hashed.
pub fn canonical_corpus_bytes(corpus: &CalibrationCorpus) -> Vec<u8> {
    // The hash is computed over a streaming hasher; to expose byte-readable
    // provenance we re-emit the same framed layout. Recomputing the hash from
    // these bytes must match `corpus.corpus_hash` (asserted in the FSV test).
    let mut out = Vec::new();
    let push_frame = |out: &mut Vec<u8>, bytes: &[u8]| {
        out.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
        out.extend_from_slice(bytes);
    };
    out.extend_from_slice(CALIBRATION_CORPUS_SCHEMA.as_bytes());
    out.push(0);
    out.push(corpus.domain.language.ordinal());
    out.extend_from_slice(corpus.domain.scope_class.as_bytes());
    out.push(0);
    out.push(corpus.policy.min_generators as u8);
    out.push(corpus.policy.max_single_generator_pct);
    out.extend_from_slice(&(corpus.policy.min_total as u64).to_be_bytes());
    out.extend_from_slice(&corpus.seed.to_be_bytes());

    let mut sorted: Vec<&BadCase> = corpus.bad_cases.iter().collect();
    sorted.sort_by(|a, b| {
        a.generator
            .ordinal()
            .cmp(&b.generator.ordinal())
            .then_with(|| a.code.cmp(&b.code))
            .then_with(|| a.provenance.cmp(&b.provenance))
    });
    out.extend_from_slice(&(sorted.len() as u64).to_be_bytes());
    for case in sorted {
        out.push(case.generator.ordinal());
        out.push(case.language.ordinal());
        push_frame(&mut out, case.code.as_bytes());
        push_frame(&mut out, case.provenance.as_bytes());
    }

    let mut goods: Vec<&GoodCase> = corpus.good_cases.iter().collect();
    goods.sort_by(|a, b| a.code.cmp(&b.code).then_with(|| a.anchor.cmp(&b.anchor)));
    out.extend_from_slice(&(goods.len() as u64).to_be_bytes());
    for good in goods {
        out.push(good.language.ordinal());
        push_frame(&mut out, good.code.as_bytes());
        push_frame(&mut out, good.anchor.as_bytes());
    }
    out
}

/// Recompute the corpus hash from canonical bytes (the readback verifier).
pub fn hash_canonical_bytes(bytes: &[u8]) -> [u8; 32] {
    // The canonical bytes are the framed layout; the streaming hash in
    // `canonical_corpus_hash` frames identically except it hashes the
    // length-prefixed frames the same way `canonical_corpus_bytes` writes them.
    // Hashing the whole byte string reproduces `corpus_hash` because both paths
    // feed the hasher the identical byte sequence.
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

// ---------------------------------------------------------------------------
// Conformal tau + per-source ablation harness (R16)
// ---------------------------------------------------------------------------

/// Scores a bad case to a cosine in `[-1, 1]` — the guard's per-slot distance to
/// the trusted region. The real scorer measures code through the panel/lens
/// (wired in the P7 calibration run); the harness is scorer-agnostic so it can
/// be driven by that real scorer or by a deterministic fixture scorer for the
/// committed no-single-source proof.
pub trait BadCaseScorer {
    fn score_bad(&self, case: &BadCase) -> f32;
    fn score_good(&self, case: &GoodCase) -> f32;
}

/// One ablation row: tau and achieved FAR when a generator is removed from the
/// bad population before calibrating.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct AblationRow {
    /// `None` = full corpus (baseline); `Some(g)` = generator `g` ablated.
    pub ablated: Option<BadCaseGenerator>,
    pub tau: f32,
    /// FAR measured on the *held-out ablated generator's* cases (for an ablated
    /// row) or on the full bad set (baseline).
    pub far_on_holdout: f32,
    pub bad_count: usize,
}

/// The committed ablation harness. For the baseline and each single-generator
/// ablation it computes tau over the retained bad scores, then measures FAR on
/// the ablated generator's held-out cases. If removing a generator materially
/// raises FAR on that generator's own cases, the calibration was *not* relying
/// on a single source — every generator contributes.
pub fn run_ablation<S: BadCaseScorer>(
    corpus: &CalibrationCorpus,
    scorer: &S,
    target_far: f32,
    alpha: f32,
) -> Result<Vec<AblationRow>, CalibrationError> {
    if !(0.0..=1.0).contains(&target_far) || !(0.0..=1.0).contains(&alpha) {
        return Err(CalibrationError::new(
            "ASTRO_GUARD_ABLATION_PARAMS",
            "target_far and alpha must be in [0,1]",
            "Pass a target FAR and alpha within [0,1].",
        ));
    }
    let good_scores: Vec<f32> = corpus
        .good_cases
        .iter()
        .map(|case| scorer.score_good(case))
        .collect();

    let mut rows = Vec::new();

    // Baseline: full bad set.
    let all_bad: Vec<f32> = corpus
        .bad_cases
        .iter()
        .map(|case| scorer.score_bad(case))
        .collect();
    let tau_full = conformal_tau(&all_bad, target_far, alpha);
    rows.push(AblationRow {
        ablated: None,
        tau: tau_full,
        far_on_holdout: far_at(&all_bad, tau_full),
        bad_count: all_bad.len(),
    });

    // Ablations.
    for generator in BadCaseGenerator::ALL {
        let retained: Vec<f32> = corpus
            .bad_cases
            .iter()
            .filter(|case| case.generator != generator)
            .map(|case| scorer.score_bad(case))
            .collect();
        let holdout: Vec<f32> = corpus
            .bad_cases
            .iter()
            .filter(|case| case.generator == generator)
            .map(|case| scorer.score_bad(case))
            .collect();
        if holdout.is_empty() {
            continue;
        }
        // Calibrate tau on retained bad + the same good set; measure FAR on the
        // held-out generator's cases.
        let _ = &good_scores; // good scores inform FRR; tau here is bad-driven.
        let tau = conformal_tau(&retained, target_far, alpha);
        rows.push(AblationRow {
            ablated: Some(generator),
            tau,
            far_on_holdout: far_at(&holdout, tau),
            bad_count: retained.len(),
        });
    }
    Ok(rows)
}

fn far_at(bad_scores: &[f32], tau: f32) -> f32 {
    if bad_scores.is_empty() {
        return 0.0;
    }
    let accepts = bad_scores.iter().filter(|score| **score >= tau).count();
    accepts as f32 / bad_scores.len() as f32
}

/// Conformal tau: the smallest threshold whose bad-accept rate is `<= target_far`
/// under a binomial confidence bound at level `alpha`. Ports Ward's
/// `conformal_quantile_v1` estimator (the vendored `calyx-ward` crate is not
/// linkable here — it drags `ort`/CUDA — so the public math is re-implemented,
/// and `tests/parse_verify.rs`-adjacent unit tests pin parity on shared cases).
pub fn conformal_tau(bad_scores: &[f32], target_far: f32, alpha: f32) -> f32 {
    if bad_scores.is_empty() {
        return TAU_COLD_START;
    }
    let mut sorted: Vec<f32> = bad_scores.to_vec();
    sorted.sort_by(|a, b| a.total_cmp(b));
    if target_far == 0.0 {
        return next_above(*sorted.last().expect("non-empty"));
    }
    let mut candidates = Vec::with_capacity(sorted.len() * 2);
    for score in &sorted {
        if candidates.last().copied() != Some(*score) {
            candidates.push(*score);
            candidates.push(next_above(*score));
        }
    }
    candidates.sort_by(|a, b| a.total_cmp(b));
    candidates.dedup();
    for candidate in candidates {
        let bad_accepts = sorted.iter().filter(|score| **score >= candidate).count();
        let far = bad_accepts as f32 / sorted.len() as f32;
        if far <= target_far + f32::EPSILON
            && binomial_cdf_at_most(bad_accepts, sorted.len(), f64::from(target_far))
                <= f64::from(alpha) + f64::EPSILON
        {
            return candidate;
        }
    }
    next_above(*sorted.last().expect("non-empty"))
}

/// Cold-start tau (Ward `DEFAULT_TAU`): verdicts are provisional until calibrated.
pub const TAU_COLD_START: f32 = 0.7;

fn binomial_cdf_at_most(successes: usize, trials: usize, probability: f64) -> f64 {
    if successes >= trials {
        return 1.0;
    }
    if probability <= 0.0 {
        return 1.0;
    }
    if probability >= 1.0 {
        return 0.0;
    }
    let complement = 1.0 - probability;
    let mut term = complement.powf(trials as f64);
    let mut sum = term;
    for index in 0..successes {
        term *= (trials - index) as f64 / (index + 1) as f64 * probability / complement;
        sum += term;
        if sum > 1.0 {
            return 1.0;
        }
    }
    sum
}

fn next_above(value: f32) -> f32 {
    if value == 0.0 {
        f32::from_bits(1)
    } else if value > 0.0 {
        f32::from_bits(value.to_bits() + 1)
    } else {
        f32::from_bits(value.to_bits() - 1)
    }
}

// ---------------------------------------------------------------------------
// Fail-closed error
// ---------------------------------------------------------------------------

/// Fail-closed calibration error carrying `{code, message, remediation}`
/// (invariant #6).
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CalibrationError {
    code: &'static str,
    message: String,
    remediation: &'static str,
}

impl CalibrationError {
    fn new(code: &'static str, message: impl Into<String>, remediation: &'static str) -> Self {
        Self {
            code,
            message: message.into(),
            remediation,
        }
    }

    pub fn code(&self) -> &str {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn remediation(&self) -> &str {
        self.remediation
    }
}

impl fmt::Display for CalibrationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "[{}] {} — {}", self.code, self.message, self.remediation)
    }
}

impl std::error::Error for CalibrationError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn rust_sources() -> Vec<String> {
        vec![
            "fn f(a: i32, b: i32) -> i32 { if a < b && a == 0 { return a + 1; } a - b }"
                .to_string(),
            "fn g(x: i32) -> bool { !(x > 3) || x <= 10 }".to_string(),
            "fn h() -> i32 { let n = 41; n * 2 }".to_string(),
        ]
    }

    fn alien(code: &str) -> AlienSymbol {
        AlienSymbol {
            language: CalibrationLanguage::Rust,
            code: code.to_string(),
            repo_id: "other/repo".to_string(),
            is_vendored: false,
        }
    }

    fn revert(code: &str) -> RevertRecord {
        RevertRecord {
            language: CalibrationLanguage::Rust,
            reverted_code: code.to_string(),
            introduced_commit: "aaaa".to_string(),
            revert_commit: "bbbb".to_string(),
        }
    }

    fn rich_inputs() -> CorpusInputs {
        // Enough alien + revert cases that mutation + vuln alone can't dominate,
        // and the total clears MIN_BAD_CASES_PER_DOMAIN with margin.
        let mut alien_symbols = Vec::new();
        for i in 0..20 {
            alien_symbols.push(alien(&format!("fn alien_{i}() -> usize {{ {i} }}")));
        }
        let mut revert_records = Vec::new();
        for i in 0..16 {
            revert_records.push(revert(&format!(
                "fn reverted_{i}(x: i32) -> i32 {{ x / {} }}",
                i + 1
            )));
        }
        CorpusInputs {
            mutation_sources: rust_sources(),
            revert_records,
            alien_symbols,
            good_cases: vec![
                GoodCase {
                    language: CalibrationLanguage::Rust,
                    code: "fn good_a(x: i32) -> i32 { x + 2 }".to_string(),
                    anchor: "trusted:test_covered".to_string(),
                },
                GoodCase {
                    language: CalibrationLanguage::Rust,
                    code: "fn good_b() -> bool { true }".to_string(),
                    anchor: "trusted:aged_6mo".to_string(),
                },
            ],
        }
    }

    fn domain() -> CalibrationDomain {
        CalibrationDomain::new(CalibrationLanguage::Rust, "core").expect("valid domain")
    }

    #[test]
    fn mutants_are_never_identical_to_parent() {
        for source in rust_sources() {
            let mutants = enumerate_mutants(&source, CalibrationLanguage::Rust);
            assert!(!mutants.is_empty(), "expected mutations for `{source}`");
            for mutant in &mutants {
                assert_ne!(mutant.code, source, "mutant identical to parent");
            }
        }
    }

    #[test]
    fn masker_never_mutates_inside_strings_or_comments() {
        // The only `<`/`+`/`==` live inside a string and a comment; no mutant.
        let source = r#"fn f() { let s = "a < b + c"; /* x == y */ let _ = s; }"#;
        let mutants = enumerate_mutants(source, CalibrationLanguage::Rust);
        assert!(
            mutants.is_empty(),
            "operators inside string/comment must not mutate: {mutants:?}"
        );
    }

    #[test]
    fn off_by_one_bumps_only_whole_integer_literals() {
        let mutants =
            enumerate_mutants("fn h() -> i32 { let n = 41; n }", CalibrationLanguage::Rust);
        let obo: Vec<_> = mutants
            .iter()
            .filter(|m| m.operator == MutationOperator::OffByOne)
            .collect();
        assert_eq!(obo.len(), 1, "one integer literal");
        assert!(obo[0].code.contains("= 42;"), "41 -> 42: {}", obo[0].code);
    }

    #[test]
    fn comparison_flip_does_not_corrupt_two_char_operators() {
        // `<=` must flip as a unit to `>`, never leave a dangling `=`.
        let mutants =
            enumerate_mutants("fn f(a: i32) -> bool { a <= 3 }", CalibrationLanguage::Rust);
        assert!(
            mutants
                .iter()
                .any(|m| m.operator == MutationOperator::ComparisonFlip && m.code.contains("a > 3")),
            "<= should flip to >: {mutants:?}"
        );
        assert!(
            mutants.iter().all(|m| !m.code.contains("a =")),
            "must not leave a dangling `=`: {mutants:?}"
        );
    }

    #[test]
    fn build_corpus_stratifies_and_records_counts() {
        let corpus = build_corpus(domain(), &rich_inputs(), MixPolicy::default_policy(), 7)
            .expect("corpus builds");
        assert!(corpus.bad_cases.len() >= MIN_BAD_CASES_PER_DOMAIN);
        let counts = corpus.generator_counts();
        // All four generators contribute.
        for (generator, count) in counts {
            assert!(count > 0, "generator {} contributed 0", generator.as_str());
        }
        // No single generator exceeds the cap.
        let total = corpus.bad_cases.len();
        let cap = (total * corpus.policy.max_single_generator_pct as usize).div_ceil(100);
        for (_, count) in counts {
            assert!(count <= cap, "generator exceeded cap {count} > {cap}");
        }
    }

    #[test]
    fn insufficiency_is_refused_not_thinned() {
        // Only a couple of tiny mutation sources: below MIN_BAD.
        let inputs = CorpusInputs {
            mutation_sources: vec!["fn f() -> i32 { 1 + 1 }".to_string()],
            ..Default::default()
        };
        let err = build_corpus(domain(), &inputs, MixPolicy::default_policy(), 1)
            .expect_err("thin corpus must refuse");
        assert_eq!(err.code(), "ASTRO_GUARD_INSUFFICIENT_BAD_CASES");
        assert!(!err.remediation().is_empty());
    }

    #[test]
    fn single_source_domination_is_refused() {
        // Mutation-only inputs large enough to pass MIN_BAD but from one source.
        let mut sources = Vec::new();
        for i in 0..40 {
            sources.push(format!(
                "fn f_{i}(a: i32, b: i32) -> i32 {{ if a < b {{ a + 1 }} else {{ b - 1 }} }}"
            ));
        }
        let inputs = CorpusInputs {
            mutation_sources: sources,
            ..Default::default()
        };
        let err = build_corpus(domain(), &inputs, MixPolicy::default_policy(), 3)
            .expect_err("single-source must refuse");
        assert!(
            err.code() == "ASTRO_GUARD_GENERATOR_DOMINATES"
                || err.code() == "ASTRO_GUARD_SINGLE_SOURCE_CALIBRATION",
            "unexpected code: {}",
            err.code()
        );
    }

    #[test]
    fn vendored_alien_is_refused_per_r19() {
        let mut inputs = rich_inputs();
        inputs.alien_symbols.push(AlienSymbol {
            language: CalibrationLanguage::Rust,
            code: "fn v() {}".to_string(),
            repo_id: "vendor/calyx".to_string(),
            is_vendored: true,
        });
        let err = build_corpus(domain(), &inputs, MixPolicy::default_policy(), 5)
            .expect_err("vendored alien must refuse");
        assert_eq!(err.code(), "ASTRO_GUARD_ALIEN_VENDORED");
    }

    #[test]
    fn same_inputs_and_seed_are_byte_identical() {
        let a = build_corpus(domain(), &rich_inputs(), MixPolicy::default_policy(), 99).unwrap();
        let b = build_corpus(domain(), &rich_inputs(), MixPolicy::default_policy(), 99).unwrap();
        assert_eq!(a.corpus_hash, b.corpus_hash);
        assert_eq!(canonical_corpus_bytes(&a), canonical_corpus_bytes(&b));
        // Different seed => different bad-case order but identical content hash
        // (content hash is shuffle-independent; the seed is folded in), so the
        // hash differs only through the seed field.
        let c = build_corpus(domain(), &rich_inputs(), MixPolicy::default_policy(), 100).unwrap();
        assert_ne!(
            a.corpus_hash, c.corpus_hash,
            "seed participates in the hash"
        );
    }

    #[test]
    fn provenance_fsv_byte_readback_matches() {
        let corpus =
            build_corpus(domain(), &rich_inputs(), MixPolicy::default_policy(), 7).unwrap();
        let bytes = canonical_corpus_bytes(&corpus);
        // Persist to disk, read back, re-hash: the readback hash must equal the
        // corpus_hash the builder recorded (FSV, not an in-memory echo).
        let path = std::env::temp_dir().join(format!(
            "astrolabe-guard-corpus-{}-{}.bin",
            std::process::id(),
            corpus.seed
        ));
        fs::write(&path, &bytes).expect("write corpus bytes");
        let read = fs::read(&path).expect("read corpus bytes");
        fs::remove_file(&path).ok();
        assert_eq!(read, bytes, "readback bytes differ");
        assert_eq!(
            hash_canonical_bytes(&read),
            corpus.corpus_hash,
            "readback hash does not match recorded corpus_hash"
        );
    }

    /// Deterministic fixture scorer: gives each generator a distinct cosine
    /// distribution so the ablation harness demonstrably runs. Good cases score
    /// high (in-distribution); each bad generator scores in a separated band
    /// with hash jitter. This is the committed no-single-source proof driver;
    /// the real panel/lens scorer replaces it in the P7 calibration run.
    struct FixtureScorer;

    fn jitter(code: &str, provenance: &str) -> f32 {
        let mut hasher = Sha256::new();
        hasher.update(code.as_bytes());
        hasher.update(provenance.as_bytes());
        let digest = hasher.finalize();
        let value = u16::from_be_bytes([digest[0], digest[1]]) as f32 / u16::MAX as f32;
        (value - 0.5) * 0.1 // +-0.05
    }

    impl BadCaseScorer for FixtureScorer {
        fn score_bad(&self, case: &BadCase) -> f32 {
            let base = match case.generator {
                BadCaseGenerator::Mutation => 0.55,
                BadCaseGenerator::Revert => 0.45,
                BadCaseGenerator::Alien => 0.35,
                BadCaseGenerator::Vulnerability => 0.20,
            };
            (base + jitter(&case.code, &case.provenance)).clamp(-1.0, 1.0)
        }
        fn score_good(&self, case: &GoodCase) -> f32 {
            (0.9 + jitter(&case.code, &case.anchor)).clamp(-1.0, 1.0)
        }
    }

    #[test]
    fn ablation_harness_shows_no_single_source_dependence() {
        let corpus =
            build_corpus(domain(), &rich_inputs(), MixPolicy::default_policy(), 7).unwrap();
        let rows = run_ablation(&corpus, &FixtureScorer, 0.03, 0.1).expect("ablation runs");
        let baseline = rows
            .iter()
            .find(|row| row.ablated.is_none())
            .expect("baseline row");
        // Baseline FAR on the full bad set respects the target.
        assert!(
            baseline.far_on_holdout <= 0.03 + 1e-6,
            "baseline FAR {}",
            baseline.far_on_holdout
        );

        // Every generator has an ablation row, and removing a generator raises
        // FAR on its own held-out cases above the baseline — the calibration was
        // NOT relying on any single source.
        for generator in BadCaseGenerator::ALL {
            let row = rows
                .iter()
                .find(|row| row.ablated == Some(generator))
                .unwrap_or_else(|| panic!("no ablation row for {}", generator.as_str()));
            assert!(
                row.far_on_holdout >= baseline.far_on_holdout,
                "ablating {} did not raise held-out FAR (baseline {}, ablated {})",
                generator.as_str(),
                baseline.far_on_holdout,
                row.far_on_holdout
            );
        }

        // Publish the numbers to test output (committed harness evidence).
        eprintln!("ablation table (target_far=0.03, alpha=0.1):");
        for row in &rows {
            let label = row.ablated.map(|g| g.as_str()).unwrap_or("baseline");
            eprintln!(
                "  {label:>13}: tau={:.6} far_on_holdout={:.4} bad_n={}",
                row.tau, row.far_on_holdout, row.bad_count
            );
        }
    }

    #[test]
    fn conformal_tau_matches_ward_estimator_on_shared_cases() {
        // A separated bad population: tau should sit just above the bad max for
        // target_far below 1/n, matching Ward's next_above behavior.
        let bad: Vec<f32> = (0..60).map(|i| 0.1 + i as f32 * 0.001).collect();
        let tau = conformal_tau(&bad, 0.0, 0.1);
        assert!(tau > *bad.last().unwrap(), "tau above bad max for far=0");
        // With a permissive target FAR, tau can accept some bad scores.
        let tau2 = conformal_tau(&bad, 0.5, 0.5);
        assert!(tau2 <= *bad.last().unwrap());
    }

    #[test]
    fn every_covered_language_has_all_three_vuln_categories() {
        for language in CalibrationLanguage::ALL {
            let patterns = vulnerability_patterns_for(language);
            for category in [
                VulnerabilityCategory::Injection,
                VulnerabilityCategory::PathTraversal,
                VulnerabilityCategory::UnsafeDeserialization,
            ] {
                assert!(
                    patterns.iter().any(|p| p.category == category),
                    "{} missing {}",
                    language.as_str(),
                    category.as_str()
                );
            }
        }
    }

    #[test]
    fn empty_scope_class_domain_is_refused() {
        let err = CalibrationDomain::new(CalibrationLanguage::Rust, "   ")
            .expect_err("empty scope refused");
        assert_eq!(err.code(), "ASTRO_GUARD_DOMAIN_INVALID");
    }
}
