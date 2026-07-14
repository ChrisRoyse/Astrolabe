//! Fail-closed emission-vocabulary parity between libcbm's code-graph emitters and
//! the Astrolabe identity spine (`SymbolLabel` / `EdgeKind`) — issue #375.
//!
//! Wave-13's real-corpus E2E surfaced CBM-emission vs spine drift the hard way: the
//! real `cbm/` corpus emitted `Decorator` nodes and `RAISES` edges the spine did not
//! admit, and each refused the whole import (`ASTRO_INGEST_SQLITE_INVALID`) only at
//! M-corpus time. This test sources the C-side vocabulary **from the emitters
//! themselves** — the literal arguments at the `cbm_gbuf_upsert_node` /
//! `cbm_gbuf_insert_edge` choke points, plus the def-label assignments/resolvers that
//! feed the node label — and fails closed when any emittable label or edge type has
//! no spine counterpart. A new emission is therefore caught here, at test time,
//! before any import runs, rather than at real-corpus E2E.
//!
//! Scope is the **code-graph** emission surface (pipeline passes + extraction + graph
//! buffer). The runtime-trace subsystem (`cbm/src/traces`) emits into a separate store
//! on a separate ingest path and is intentionally out of scope here.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use astrolabe_domain::{EdgeKind, SymbolLabel};

/// The named fail-closed deficit this parity check raises. Mirrors the ingest
/// admission code so a drift here reads the same as a drift caught at import.
const PARITY_DEFICIT: &str = "ASTRO_INGEST_SQLITE_INVALID";

/// Locate the `cbm/` source root from the crate manifest dir.
fn cbm_root() -> PathBuf {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../cbm");
    root.canonicalize()
        .unwrap_or_else(|err| panic!("cbm/ source root not found at {}: {err}", root.display()))
}

/// The code-graph emitter source files: the pipeline passes, the graph buffer, and
/// the extraction TUs (including the LSP def emitters). Vendored grammars and the
/// runtime-trace subsystem are excluded.
fn emitter_files(root: &Path) -> Vec<(String, String)> {
    let mut dirs = vec![
        root.join("src/pipeline"),
        root.join("src/graph_buffer"),
        root.join("internal/cbm"),
        root.join("internal/cbm/lsp"),
        root.join("internal/cbm/lsp/generated"),
    ];
    let mut out = Vec::new();
    while let Some(dir) = dirs.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let name = path.to_string_lossy().replace('\\', "/");
            if name.contains("/vendored/") || name.contains("/traces/") {
                continue;
            }
            if path.is_file() && path.extension().is_some_and(|ext| ext == "c") {
                let content = std::fs::read_to_string(&path)
                    .unwrap_or_else(|err| panic!("read {}: {err}", path.display()));
                out.push((name, content));
            }
        }
    }
    assert!(
        !out.is_empty(),
        "{PARITY_DEFICIT}: found no libcbm emitter sources under {}",
        root.display()
    );
    out
}

/// Extract the argument expressions of every `fn_name(...)` call, balanced-paren and
/// multi-line aware, respecting string/char literals and `//` line comments so a
/// comma or paren inside a literal or comment never splits an argument.
fn call_arguments(source: &str, fn_name: &str) -> Vec<Vec<String>> {
    let bytes = source.as_bytes();
    let needle = format!("{fn_name}(");
    let mut calls = Vec::new();
    let mut search = 0usize;
    while let Some(rel) = source[search..].find(&needle) {
        let open = search + rel + needle.len() - 1; // index of '('
        // Reject a match that is part of a longer identifier (e.g. `x_fn_name(`).
        let prev_ok = open
            .checked_sub(needle.len())
            .and_then(|i| bytes.get(i))
            .is_none_or(|b| !(b.is_ascii_alphanumeric() || *b == b'_'));
        search = open + 1;
        if !prev_ok {
            continue;
        }
        let mut depth = 0i32;
        let mut i = open;
        let mut args = vec![String::new()];
        let mut in_str = false;
        let mut in_char = false;
        let mut done = false;
        while i < bytes.len() {
            let c = bytes[i] as char;
            if in_str {
                args.last_mut().unwrap().push(c);
                if c == '\\' && i + 1 < bytes.len() {
                    args.last_mut().unwrap().push(bytes[i + 1] as char);
                    i += 2;
                    continue;
                }
                if c == '"' {
                    in_str = false;
                }
                i += 1;
                continue;
            }
            if in_char {
                if c == '\\' && i + 1 < bytes.len() {
                    i += 2;
                    continue;
                }
                if c == '\'' {
                    in_char = false;
                }
                i += 1;
                continue;
            }
            if c == '/' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
                continue;
            }
            match c {
                '"' => {
                    in_str = true;
                    args.last_mut().unwrap().push(c);
                }
                '\'' => in_char = true,
                '(' => {
                    depth += 1;
                    if depth > 1 {
                        args.last_mut().unwrap().push(c);
                    }
                }
                ')' => {
                    depth -= 1;
                    if depth == 0 {
                        done = true;
                        break;
                    }
                    args.last_mut().unwrap().push(c);
                }
                ',' if depth == 1 => args.push(String::new()),
                _ => args.last_mut().unwrap().push(c),
            }
            i += 1;
        }
        if done {
            calls.push(args.into_iter().map(|a| a.trim().to_string()).collect());
        }
    }
    calls
}

/// Extract the contents of every `"..."` string literal in a C expression.
fn string_literals(expr: &str) -> Vec<String> {
    let bytes = expr.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i] == b'"' {
            let mut lit = String::new();
            i += 1;
            while i < bytes.len() && bytes[i] != b'"' {
                if bytes[i] == b'\\' && i + 1 < bytes.len() {
                    lit.push(bytes[i + 1] as char);
                    i += 2;
                    continue;
                }
                lit.push(bytes[i] as char);
                i += 1;
            }
            out.push(lit);
        }
        i += 1;
    }
    out
}

/// True when `expr` is a bare identifier (a variable whose assignments we resolve).
fn simple_identifier(expr: &str) -> Option<&str> {
    let e = expr.trim();
    (!e.is_empty()
        && e.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        && !e.chars().next().unwrap().is_ascii_digit())
    .then_some(e)
}

/// Edge-type shape: all-caps with digits/underscores, e.g. `RAISES`, `CROSS_HTTP_CALLS`.
fn is_edge_shape(token: &str) -> bool {
    token.len() >= 3
        && token.bytes().next().is_some_and(|b| b.is_ascii_uppercase())
        && token
            .bytes()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_')
}

/// Node-label shape: PascalCase (`Function`, `EnumMember`) — an uppercase initial
/// followed by a lowercase letter. This cleanly separates labels from the all-caps
/// edge types and HTTP-method literals that live in the same files.
fn is_label_shape(token: &str) -> bool {
    let mut chars = token.chars();
    chars.next().is_some_and(|c| c.is_ascii_uppercase())
        && chars.next().is_some_and(|c| c.is_ascii_lowercase())
        && token.chars().all(|c| c.is_ascii_alphabetic())
}

/// Collect every code-graph edge-type token the emitters can produce: the 4th
/// argument of each `cbm_gbuf_insert_edge` call — resolved through a simple
/// edge-type variable's assignments (`edge_type = cond ? "THROWS" : "RAISES"`) when
/// the argument is a bare identifier. Member-expression arguments (`se->type`) are
/// edge copies of an already-emitted type and carry no new vocabulary.
fn emitted_edge_types(files: &[(String, String)]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (_name, content) in files {
        for call in call_arguments(content, "cbm_gbuf_insert_edge") {
            let Some(type_arg) = call.get(3) else {
                continue;
            };
            let lits = string_literals(type_arg);
            if !lits.is_empty() {
                out.extend(lits.into_iter().filter(|t| is_edge_shape(t)));
            } else if let Some(ident) = simple_identifier(type_arg) {
                for line in content.lines() {
                    let trimmed = line.trim_start();
                    let after = trimmed
                        .strip_prefix(ident)
                        .or_else(|| trimmed.split(ident).nth(1).map(|_| ""));
                    if after.is_some() && line.contains(&format!("{ident} =")) {
                        out.extend(string_literals(line).into_iter().filter(|t| is_edge_shape(t)));
                    }
                }
            }
        }
    }
    out
}

/// Collect every code-graph node label the emitters can produce: the 2nd argument
/// of each `cbm_gbuf_upsert_node` call, plus the def-label assignments/resolvers that
/// feed a dynamic `def->label`.
fn emitted_node_labels(files: &[(String, String)]) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for (_name, content) in files {
        // (1) Direct literal / ternary-fallback labels at the emit choke point.
        for call in call_arguments(content, "cbm_gbuf_upsert_node") {
            if let Some(label_arg) = call.get(1) {
                out.extend(string_literals(label_arg).into_iter().filter(|t| is_label_shape(t)));
            }
        }
        // (2) def-label assignments (`label = "Class"`, `def.label = "Method"`,
        //     `def->label = "Field"`) and label-resolver returns (`class_label_for_kind`
        //     → `return "Interface"`). The resolver return is scoped to functions whose
        //     name contains "label" so type-name resolvers (ts_lsp `return "Boolean"`)
        //     are not mistaken for node labels.
        let mut current_fn = String::new();
        for line in content.lines() {
            if let Some(name) = c_function_name(line) {
                current_fn = name;
            }
            let is_label_assign = line.contains("label =") || line.contains("label=");
            let is_label_return =
                line.trim_start().starts_with("return ") && current_fn.to_lowercase().contains("label");
            if is_label_assign || is_label_return {
                out.extend(string_literals(line).into_iter().filter(|t| is_label_shape(t)));
            }
        }
    }
    out
}

/// If `line` is a top-level C function definition header (`ret_type name(...`), return
/// the function's name. Heuristic: an unindented line containing `name(` where the
/// text before `name` looks like a return type.
fn c_function_name(line: &str) -> Option<String> {
    if line.starts_with(char::is_whitespace) || line.is_empty() {
        return None;
    }
    let paren = line.find('(')?;
    let head = &line[..paren];
    let name: String = head
        .chars()
        .rev()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect::<String>()
        .chars()
        .rev()
        .collect();
    // Require something (a return type / qualifier) before the name.
    (!name.is_empty() && head.trim_end().len() > name.len()).then_some(name)
}

#[test]
fn code_graph_edge_types_all_have_a_spine_counterpart() {
    let root = cbm_root();
    let files = emitter_files(&root);
    let emitted = emitted_edge_types(&files);
    assert!(
        emitted.len() >= 20,
        "{PARITY_DEFICIT}: extracted only {} edge types from the emitters — the scanner is not \
         reaching the insert_edge call sites",
        emitted.len()
    );
    let orphans: Vec<&String> = emitted
        .iter()
        .filter(|edge| EdgeKind::from_cbm_type(edge).is_none())
        .collect();
    assert!(
        orphans.is_empty(),
        "{PARITY_DEFICIT}: libcbm emits edge type(s) with no EdgeKind counterpart: {orphans:?}. \
         Admit them in astrolabe_domain::EdgeKind (mirror the Decorator/RAISES precedent) before \
         they refuse a real import."
    );
}

#[test]
fn code_graph_node_labels_all_have_a_spine_counterpart() {
    let root = cbm_root();
    let files = emitter_files(&root);
    let emitted = emitted_node_labels(&files);
    assert!(
        emitted.len() >= 15,
        "{PARITY_DEFICIT}: extracted only {} node labels from the emitters — the scanner is not \
         reaching the upsert_node / def-label sites",
        emitted.len()
    );
    let orphans: Vec<&String> = emitted
        .iter()
        .filter(|label| SymbolLabel::from_cbm_label(label).is_none())
        .collect();
    assert!(
        orphans.is_empty(),
        "{PARITY_DEFICIT}: libcbm emits node label(s) with no SymbolLabel counterpart: {orphans:?}. \
         Admit them in astrolabe_domain::SymbolLabel before they refuse a real import."
    );
}

#[test]
fn planted_new_emission_trips_the_check() {
    // A synthetic emitter TU carrying an edge type and a node label the spine does
    // not know. The exact same extraction+validation the real check runs must flag
    // both — proving a NEW emission is caught here, before any import.
    let planted = vec![(
        "planted.c".to_string(),
        r#"
void demo(cbm_gbuf_t *g) {
    cbm_gbuf_upsert_node(g, "Frobnicator", "x", "q", "f.c", 1, 2, "{}");
    cbm_gbuf_insert_edge(g, 1, 2, "TELEPORTS", "{}");
    const char *edge_type = cond ? "CALLS" : "WARPS_TO";
    cbm_gbuf_insert_edge(g, 1, 2, edge_type, "{}");
}
"#
        .to_string(),
    )];

    let edges = emitted_edge_types(&planted);
    assert!(edges.contains("TELEPORTS"), "literal edge not extracted: {edges:?}");
    assert!(edges.contains("WARPS_TO"), "variable-resolved edge not extracted: {edges:?}");
    let edge_orphans: Vec<&String> = edges
        .iter()
        .filter(|e| EdgeKind::from_cbm_type(e).is_none())
        .collect();
    assert_eq!(
        edge_orphans.len(),
        2,
        "planted edge drift must trip the check; orphans = {edge_orphans:?}"
    );

    let labels = emitted_node_labels(&planted);
    assert!(labels.contains("Frobnicator"), "planted label not extracted: {labels:?}");
    assert!(
        SymbolLabel::from_cbm_label("Frobnicator").is_none(),
        "planted label must be a spine orphan"
    );
}

#[test]
fn scanner_argument_parser_is_literal_and_comment_safe() {
    // A comma inside a string literal or a // comment must not split an argument,
    // and a nested call's parens must balance.
    let src = r#"
        cbm_gbuf_insert_edge(g, id(a, b), t, "HAS, COMMA", "{}"); // trailing, comma
    "#;
    let calls = call_arguments(src, "cbm_gbuf_insert_edge");
    assert_eq!(calls.len(), 1);
    assert_eq!(calls[0].len(), 5, "args mis-split: {:?}", calls[0]);
    assert_eq!(string_literals(&calls[0][3]), vec!["HAS, COMMA".to_string()]);
}
