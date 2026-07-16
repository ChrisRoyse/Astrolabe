use std::fs::File;
use std::io::Read;
use std::path::Path;

use calyx_aster::manifest::ManifestStore;
use serde_json::json;

use crate::error::{CliError, CliResult};
use crate::output::print_json;
use crate::readback_vault::{ensure_native_aster_vault, not_a_vault};

/// Native Aster vaults carry a `CURRENT` pointer file naming the live
/// immutable `manifest-<seq>.json`; a Leapable shadow vault has no `CURRENT`.
const NATIVE_CURRENT_FILE: &str = "CURRENT";

/// Leapable shadow vaults carry this binary magic at the start of `MANIFEST`.
const SHADOW_MANIFEST_MAGIC: &[u8] = b"CXSHDW1!";
const SHADOW_MANIFEST_FILE: &str = "MANIFEST";

/// `readback --vault <dir> --show-manifest`.
///
/// Auto-detects the vault format from its on-disk bytes (issue #1262) and
/// dispatches to the matching reader, instead of assuming every vault is a
/// Leapable shadow vault. Detection order is content-first:
///
/// 1. If `MANIFEST` begins with the shadow magic `CXSHDW1!`, read the shadow
///    manifest (and surface any shadow-specific corruption verbatim).
/// 2. Otherwise, if a native `CURRENT` pointer exists, read the native Aster
///    manifest via [`ManifestStore::load_current`].
/// 3. Otherwise fail closed with `CALYX_NOT_A_VAULT`; the target is not a
///    materialized vault of either kind.
///
/// Before this routed by format, a valid native vault reported the misleading
/// `CALYX_MANIFEST_CORRUPT: shadow manifest magic mismatch` because the shadow
/// reader was parsing the native JSON `MANIFEST` mirror.
pub fn readback_vault_manifest(vault: &Path) -> CliResult {
    if is_shadow_vault(vault)? {
        return crate::leapable::readback_shadow_manifest(vault);
    }
    if vault.join(NATIVE_CURRENT_FILE).is_file() {
        ensure_native_aster_vault(vault)?;
        return readback_native_manifest(vault);
    }
    Err(not_a_vault(
        vault,
        "missing native CURRENT pointer and shadow MANIFEST magic",
    ))
}

/// Content-based detection of a Leapable shadow vault (issue #1262).
///
/// A shadow vault's `MANIFEST` begins with `CXSHDW1!`; a native Aster vault's
/// `MANIFEST` is a JSON mirror that begins with `{`. Dispatching by the bytes
/// prevents a valid native vault from being misreported as a corrupt shadow
/// vault.
fn is_shadow_vault(vault: &Path) -> CliResult<bool> {
    let path = vault.join(SHADOW_MANIFEST_FILE);
    let mut file = match File::open(&path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(CliError::runtime(format!(
                "open {} while detecting vault format: {error}",
                path.display()
            )));
        }
    };
    let mut magic = [0u8; SHADOW_MANIFEST_MAGIC.len()];
    match file.read_exact(&mut magic) {
        Ok(()) => Ok(magic.as_slice() == SHADOW_MANIFEST_MAGIC),
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => Ok(false),
        Err(error) => Err(CliError::runtime(format!(
            "read {} while detecting vault format: {error}",
            path.display()
        ))),
    }
}

/// Reads and prints the full native Aster manifest, tagged with
/// `vault_format: "native-aster"` so a consumer can tell it apart from the
/// shadow readback shape (which carries `magic`/`mode` fields).
fn readback_native_manifest(vault: &Path) -> CliResult {
    let manifest = ManifestStore::open(vault).load_current()?;
    let manifest_json = serde_json::to_value(&manifest)
        .map_err(|error| CliError::runtime(format!("serialize vault manifest: {error}")))?;
    print_json(&json!({
        "vault_format": "native-aster",
        "manifest": manifest_json,
    }))
}

/// `readback vault-manifest --field <name> --vault <dir>` - one native field.
pub fn readback_vault_manifest_field(vault: &Path, field: &str) -> CliResult {
    ensure_native_aster_vault(vault)?;
    let manifest = ManifestStore::open(vault).load_current()?;
    let manifest_json = serde_json::to_value(&manifest)
        .map_err(|error| CliError::runtime(format!("serialize vault manifest: {error}")))?;
    let value = manifest_json
        .get(field)
        .ok_or_else(|| CliError::usage(format!("manifest field `{field}` not found")))?;
    print_json(value)
}
