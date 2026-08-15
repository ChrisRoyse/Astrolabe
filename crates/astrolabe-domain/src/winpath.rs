//! Windows extended-length (`\\?\`) path normalization for the SQLite open sites
//! of the per-project store family (#412).
//!
//! # Why this exists
//!
//! `rusqlite` hands the database path string straight to the C `sqlite3_open_v2`.
//! SQLite's bundled Windows VFS converts that UTF-8 string to UTF-16 and calls
//! `CreateFileW` **without** the extended-length `\\?\` prefix, so any total path
//! over the legacy `MAX_PATH` (260) budget fails with `SQLITE_CANTOPEN`
//! regardless of the process/OS long-path opt-in (manifest `longPathAware` +
//! registry `LongPathsEnabled`, which is `0` by default on end-user machines).
//! Rust's own `std::fs` already bypasses `MAX_PATH` internally (it converts long
//! absolute paths to verbatim form via `maybe_verbatim`/`get_long_path`), so the
//! Calyx vault opens and every `std::fs` operation are already long-path-safe —
//! but `rusqlite`/SQLite bypass `std::fs` entirely and therefore are not.
//!
//! The robust, machine-independent fix is to hand SQLite an already
//! `\\?\`-prefixed absolute path (the same approach SQLite's own Cygwin build
//! uses). In that namespace Win32 performs **no** normalization: forward slashes
//! are not translated to backslashes, `.`/`..` are not resolved, and the path
//! must be absolute. This helper therefore canonicalizes to an absolute
//! backslash form first (via [`std::path::absolute`], which calls
//! `GetFullPathNameW`) before adding the prefix.
//!
//! # Determinism
//!
//! This is a pure function of the input path, not a try-long-fall-back-short
//! fallback: paths below [`LEGACY_PATH_THRESHOLD`] are returned byte-for-byte
//! unchanged (so short/normal stores open exactly as before), and paths at or
//! over the threshold are always returned in the single `\\?\` form. The
//! threshold mirrors the C-side `cbm_utf8_to_wide_path` (240), leaving headroom
//! under 260 for SQLite's `-wal`/`-shm`/`-journal` sibling suffixes and the
//! terminating NUL. It is a structural `MAX_PATH`-derived constant, not a tunable.

use std::path::Path;

/// UTF-8 byte length at or above which a path is emitted in `\\?\` extended-length
/// form. Below it the path is returned unchanged so short stores keep their exact
/// pre-#412 open form. 240 mirrors the C `cbm_utf8_to_wide_path` barrier: it
/// leaves 20 bytes under the 260 `MAX_PATH` budget for the longest SQLite sibling
/// suffix (`-journal`, 8 bytes) plus the terminating NUL.
pub const LEGACY_PATH_THRESHOLD: usize = 240;

/// Return the path string to hand to `rusqlite`/SQLite so the bundled Windows VFS
/// can open it beyond the legacy `MAX_PATH` (260) limit.
///
/// On Windows: a path already in verbatim (`\\?\`) form, or one whose absolute
/// UTF-8 form is shorter than [`LEGACY_PATH_THRESHOLD`], is returned unchanged;
/// otherwise the absolute path is emitted in `\\?\` (drive) or `\\?\UNC\` (UNC)
/// extended-length form. On non-Windows targets the path is returned unchanged.
///
/// # Errors
///
/// Fails closed with an [`std::io::Error`] when the path cannot be made absolute
/// (e.g. an empty path or a current-directory lookup failure) or is not valid
/// UTF-8 — the `\\?\` prefix cannot be applied blind, so the caller must surface
/// a coded open failure rather than silently opening a `MAX_PATH`-bound path.
#[cfg(windows)]
pub fn sqlite_open_path(path: &Path) -> std::io::Result<String> {
    use std::io::{Error, ErrorKind};

    let non_utf8 = || {
        Error::new(
            ErrorKind::InvalidInput,
            format!(
                "ASTRO_STORE_PATH_NON_UTF8: store path {} is not valid UTF-8 so the \\\\?\\ \
                 extended-length prefix cannot be applied; remediation: point CBM_CACHE_DIR at a \
                 UTF-8 store path",
                path.display()
            ),
        )
    };

    if let Some(text) = path.to_str()
        && (text.starts_with(r"\\?\") || text.starts_with(r"\??\"))
    {
        // Already verbatim/NT form — never double-prefix.
        return Ok(text.to_owned());
    }

    // `std::path::absolute` normalizes `/`->`\`, resolves `.`/`..`, and makes the
    // path absolute against the CWD — exactly the base the legacy open would use —
    // without touching the filesystem (unlike `canonicalize`, which can fail on a
    // not-yet-created database file).
    let absolute = std::path::absolute(path)?;
    let absolute = absolute.to_str().ok_or_else(non_utf8)?;

    if absolute.len() < LEGACY_PATH_THRESHOLD {
        // Short store — hand SQLite the original bytes, byte-identical to pre-#412.
        return path.to_str().map(str::to_owned).ok_or_else(non_utf8);
    }
    if absolute.starts_with(r"\\?\") || absolute.starts_with(r"\??\") {
        return Ok(absolute.to_owned());
    }
    if let Some(unc) = absolute.strip_prefix(r"\\") {
        // UNC `\\server\share\...` -> `\\?\UNC\server\share\...`
        Ok(format!(r"\\?\UNC\{unc}"))
    } else {
        // Drive `C:\...` -> `\\?\C:\...`
        Ok(format!(r"\\?\{absolute}"))
    }
}

/// Return a SQLite URI that opens one quiescent database image without creating
/// or consulting rollback/WAL coordination sidecars.
///
/// `immutable=1` is valid only when the caller has already established that the
/// database image cannot change for the connection lifetime. SQLite then skips
/// locking and change detection, so using this for a live database would permit
/// stale or corrupt answers. The URI retains the native long-path normalization
/// from [`sqlite_open_path`] and percent-encodes every byte outside SQLite's
/// unreserved path set.
///
/// # Errors
///
/// Returns the same path-normalization errors as [`sqlite_open_path`].
pub fn sqlite_immutable_uri(path: &Path) -> std::io::Result<String> {
    let open_path = sqlite_open_path(path)?;
    let mut uri = String::with_capacity(open_path.len().saturating_mul(3).saturating_add(36));
    uri.push_str("file:");
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    for byte in open_path.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'/') {
            uri.push(char::from(byte));
        } else {
            uri.push('%');
            uri.push(char::from(HEX[usize::from(byte >> 4)]));
            uri.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    uri.push_str("?mode=ro&immutable=1&cache=private");
    Ok(uri)
}

/// Non-Windows stub: extended-length prefixing is a Win32 concept, so the path is
/// returned unchanged. (ASTROLABE is Windows-only until the deferred port phase.)
///
/// # Errors
///
/// Fails when the path is not valid UTF-8.
#[cfg(not(windows))]
pub fn sqlite_open_path(path: &Path) -> std::io::Result<String> {
    path.to_str().map(str::to_owned).ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!("store path {} is not valid UTF-8", path.display()),
        )
    })
}
