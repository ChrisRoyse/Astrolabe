use std::collections::BTreeSet;

pub fn normalize_bindings(bindings: &str) -> String {
    let bindings = bindings.replace("\r\n", "\n");
    let enum_types = enum_type_names(&bindings);
    let mut normalized = String::with_capacity(bindings.len());

    for line in bindings.lines() {
        let trimmed = line.trim();
        if let Some(name) = enum_alias_name(trimmed, &enum_types) {
            normalized.push_str("pub type ");
            normalized.push_str(name);
            normalized.push_str(" = __bindgen_c_enum;");
        } else {
            normalized.push_str(trimmed);
        }
        normalized.push('\n');
    }

    normalized.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn enum_type_names(bindings: &str) -> BTreeSet<&str> {
    bindings
        .lines()
        .filter_map(|line| {
            let declaration = line.trim().strip_prefix("pub const ")?;
            let (constant, rest) = declaration.split_once(':')?;
            let (type_name, _) = rest.split_once('=')?;
            let type_name = type_name.trim();
            constant
                .starts_with(&format!("{type_name}_"))
                .then_some(type_name)
        })
        .collect()
}

fn enum_alias_name<'a>(line: &'a str, enum_types: &BTreeSet<&str>) -> Option<&'a str> {
    let declaration = line.strip_prefix("pub type ")?;
    let (name, value) = declaration.split_once(" = ")?;
    let is_c_int = matches!(value, "::std::os::raw::c_int;" | "::std::os::raw::c_uint;");
    (is_c_int && enum_types.contains(name)).then_some(name)
}

/// The exact attribute bindgen 0.72 places on every generated layout test.
const LAYOUT_TEST_ATTRIBUTE: &str = "#[allow(clippy::unnecessary_operation, clippy::identity_op)]";
/// The opening line of a bindgen 0.72 layout-test block.
const LAYOUT_TEST_OPENER: &str = "const _: () = {";

/// Remove bindgen's compile-time layout-test blocks (#192).
///
/// bindgen 0.72 emits each layout test as
/// `#[allow(clippy::unnecessary_operation, clippy::identity_op)]`
/// followed by `const _: () = { ... };`. The build script performs a single
/// libclang parse producing a superset with layout tests enabled; the
/// committed `src/bindings.rs` is that output without the layout-test blocks.
/// Any drift this stripper misses fails the build-time normalize-compare
/// against the committed bindings, so it degrades loudly, never silently.
pub fn strip_layout_tests(bindings: &str) -> String {
    let bindings = bindings.replace("\r\n", "\n");
    let mut stripped = String::with_capacity(bindings.len());
    let mut lines = bindings.lines().peekable();

    while let Some(line) = lines.next() {
        let is_layout_test = line.trim() == LAYOUT_TEST_ATTRIBUTE
            && lines
                .peek()
                .is_some_and(|next| next.trim_start() == LAYOUT_TEST_OPENER);
        if !is_layout_test {
            stripped.push_str(line);
            stripped.push('\n');
            continue;
        }
        let mut depth: i64 = 0;
        let mut entered_body = false;
        for body_line in lines.by_ref() {
            depth += body_line.matches('{').count() as i64;
            depth -= body_line.matches('}').count() as i64;
            if depth > 0 {
                entered_body = true;
            }
            if entered_body && depth <= 0 {
                break;
            }
        }
    }
    stripped
}
