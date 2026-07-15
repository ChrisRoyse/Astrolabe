use std::path::Path;

use crate::error::{CliError, CliResult};

pub(crate) fn vault_template_source(path: &Path) -> CliResult<String> {
    Ok(format!("vault:{}", canonical_protocol_path(path)?))
}

fn canonical_protocol_path(path: &Path) -> CliResult<String> {
    let canonical = path.canonicalize()?;
    let raw = canonical.to_str().ok_or_else(|| {
        CliError::io(format!(
            "canonical path {} is not valid UTF-8",
            canonical.display()
        ))
    })?;
    Ok(normalize_windows_extended_prefix(raw).replace('\\', "/"))
}

fn normalize_windows_extended_prefix(raw: &str) -> &str {
    raw.strip_prefix(r"\\?\").unwrap_or(raw)
}
