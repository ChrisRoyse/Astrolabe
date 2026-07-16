use std::fs;
use std::io::ErrorKind;
use std::path::Path;

use calyx_core::CalyxError;

use crate::error::{CliError, CliResult};

const CURRENT_FILE: &str = "CURRENT";
const MANIFEST_FILE: &str = "MANIFEST";
const MANIFEST_PREFIX: &str = "manifest-";
const MANIFEST_SUFFIX: &str = ".json";

/// Stable readback code for a `--vault` argument that is not a native Aster
/// vault root. This is CLI-local, not a PRD 18 catalog entry.
pub(crate) const CALYX_NOT_A_VAULT: &str = "CALYX_NOT_A_VAULT";

const NOT_A_VAULT_REMEDIATION: &str = "point --vault at a materialized native Calyx/Aster vault root containing CURRENT, \
     MANIFEST, and the immutable manifest file named by CURRENT; create or materialize \
     the vault before running readback";

pub(crate) fn ensure_native_aster_vault(vault: &Path) -> CliResult {
    let Some(metadata) = metadata_if_present(vault, "vault root")? else {
        return Err(not_a_vault(vault, "path does not exist"));
    };
    if !metadata.is_dir() {
        return Err(not_a_vault(vault, "path is not a directory"));
    }

    let current_path = vault.join(CURRENT_FILE);
    require_regular_file(vault, &current_path, "missing CURRENT pointer file")?;
    require_regular_file(
        vault,
        &vault.join(MANIFEST_FILE),
        "missing MANIFEST mirror file",
    )?;

    let pointer_bytes = fs::read(&current_path).map_err(|error| {
        CliError::io(format!(
            "read {} while validating native vault root: {error}",
            current_path.display()
        ))
    })?;
    let pointer = std::str::from_utf8(&pointer_bytes)
        .map_err(|error| not_a_vault(vault, format!("CURRENT pointer is not UTF-8: {error}")))?
        .trim();
    if !valid_manifest_filename(pointer) {
        return Err(not_a_vault(
            vault,
            "CURRENT does not point at an immutable manifest-<seq>.json file",
        ));
    }

    require_regular_file(
        vault,
        &vault.join(pointer),
        format!("CURRENT points at missing immutable manifest file {pointer}"),
    )
}

pub(crate) fn not_a_vault(vault: &Path, detail: impl Into<String>) -> CliError {
    CliError::Calyx(CalyxError {
        code: CALYX_NOT_A_VAULT,
        message: format!(
            "{} is not a native Calyx/Aster vault root: {}",
            vault.display(),
            detail.into()
        ),
        remediation: NOT_A_VAULT_REMEDIATION,
    })
}

fn require_regular_file(vault: &Path, path: &Path, missing_detail: impl Into<String>) -> CliResult {
    let Some(metadata) = metadata_if_present(path, "vault control file")? else {
        return Err(not_a_vault(vault, missing_detail));
    };
    if !metadata.is_file() {
        return Err(not_a_vault(
            vault,
            format!("{} is not a regular file", path.display()),
        ));
    }
    Ok(())
}

fn metadata_if_present(path: &Path, context: &str) -> CliResult<Option<fs::Metadata>> {
    match fs::metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(None),
        Err(error) => Err(CliError::io(format!(
            "stat {} while validating {context}: {error}",
            path.display()
        ))),
    }
}

fn valid_manifest_filename(name: &str) -> bool {
    if !name.starts_with(MANIFEST_PREFIX) || !name.ends_with(MANIFEST_SUFFIX) {
        return false;
    }
    let digits = &name[MANIFEST_PREFIX.len()..name.len() - MANIFEST_SUFFIX.len()];
    !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit())
}
