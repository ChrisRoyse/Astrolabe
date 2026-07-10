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
