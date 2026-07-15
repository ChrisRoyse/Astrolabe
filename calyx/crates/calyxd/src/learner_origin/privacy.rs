use serde_json::Value;

const PRIVATE_MARKERS: [&str; 6] = [
    "secret",
    "password",
    "payment",
    "admin",
    "private-token",
    "data-calyx-private",
];

pub fn reject_private_material(value: &Value) -> Result<(), String> {
    scan_value(value, "$")
}

fn scan_value(value: &Value, path: &str) -> Result<(), String> {
    match value {
        Value::Object(map) => {
            for (key, value) in map {
                reject_text(key, &format!("{path}.{key}"))?;
                scan_value(value, &format!("{path}.{key}"))?;
            }
        }
        Value::Array(items) => {
            for (index, value) in items.iter().enumerate() {
                scan_value(value, &format!("{path}[{index}]"))?;
            }
        }
        Value::String(text) => reject_text(text, path)?,
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

fn reject_text(text: &str, path: &str) -> Result<(), String> {
    let lower = text.to_ascii_lowercase();
    for marker in PRIVATE_MARKERS {
        if lower.contains(marker) {
            return Err(format!("private marker `{marker}` at {path}"));
        }
    }
    Ok(())
}
