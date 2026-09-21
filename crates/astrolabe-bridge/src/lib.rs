#![deny(unsafe_op_in_unsafe_fn)]

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::error::Error;
use std::ffi::{CStr, CString, NulError};
use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::marker::PhantomData;
use std::os::raw::{c_char, c_int, c_ulong, c_void};
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::ptr::{self, NonNull};
use std::rc::Rc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::thread::{self, ThreadId};

use sha2::{Digest, Sha256};

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

/// Publishes one already-synced file under a new name without replacing an
/// existing target. Windows requests write-through namespace publication; the
/// caller remains responsible for byte readback and pending-name cleanup.
#[cfg(windows)]
pub fn publish_file_no_replace_write_through(source: &Path, target: &Path) -> std::io::Result<()> {
    use std::os::windows::ffi::OsStrExt as _;
    use windows_sys::Win32::Storage::FileSystem::{MOVEFILE_WRITE_THROUGH, MoveFileExW};

    let mut source_wide = source.as_os_str().encode_wide().collect::<Vec<_>>();
    let mut target_wide = target.as_os_str().encode_wide().collect::<Vec<_>>();
    if source_wide.contains(&0) || target_wide.contains(&0) {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "immutable publication path contains an interior NUL",
        ));
    }
    source_wide.push(0);
    target_wide.push(0);
    // SAFETY: both vectors are NUL-terminated and remain live for the call;
    // MoveFileExW retains neither pointer. Omitting REPLACE_EXISTING preserves
    // the no-replace contract.
    if unsafe {
        MoveFileExW(
            source_wide.as_ptr(),
            target_wide.as_ptr(),
            MOVEFILE_WRITE_THROUGH,
        )
    } == 0
    {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Publishes one already-synced file under a new name without replacing an
/// existing target. The caller remains responsible for byte readback and
/// pending-name cleanup.
#[cfg(not(windows))]
pub fn publish_file_no_replace_write_through(source: &Path, target: &Path) -> std::io::Result<()> {
    fs::hard_link(source, target)?;
    fs::remove_file(source)
}

fn initialize_cbm_allocator() -> Result<(), BridgeError> {
    cbm_sys::initialize_allocator_bindings_first()
        .map_err(|error| envelope(error.code, error.message, error.remediation))
}

/// Make process shutdown visible to the exact supervised index child, if one
/// exists. This signal is intentionally sticky: callers use it only while the
/// owning MCP worker is terminating, so no later mutation may be admitted in
/// the same process generation.
pub fn request_supervised_index_shutdown() {
    // SAFETY: the native entry has no pointer arguments and performs one atomic
    // store. It is explicitly callable from a thread other than the runner's
    // thread so a lifecycle owner can cancel a blocking supervised call.
    unsafe { cbm_sys::cbm_mcp_index_supervisor_request_cancel() };
}

/// The C-side reserved store-dir sidecar suffix, re-exported from the
/// bindgen-surfaced libcbm macro (`CBM_ASTRO_LOWERED_DB_SUFFIX` in
/// `cbm/src/mcp/mcp.h`). The value is a NUL-terminated byte array
/// (`b".astrolabe-lowered.db\0"`). Downstream crates bind their write-side
/// suffix constant to this at compile time so the two halves of the reserved-
/// suffix contract cannot drift and re-open the phantom-project bug (#414).
pub use cbm_sys::CBM_ASTRO_LOWERED_DB_SUFFIX;

/// The C-side reserved store-dir sidecar PREFIX for the transient
/// git-archaeology scratch stores (`.astrolabe-archaeology-<nonce>.db`),
/// re-exported from the bindgen-surfaced libcbm macro
/// (`CBM_ASTRO_ARCHAEOLOGY_DB_PREFIX` in `cbm/src/mcp/mcp.h`). Same drift
/// contract as [`CBM_ASTRO_LOWERED_DB_SUFFIX`] (#414).
pub use cbm_sys::CBM_ASTRO_ARCHAEOLOGY_DB_PREFIX;

pub fn parent_roots() -> (&'static str, &'static str) {
    (
        astrolabe_domain::calyx_vendor_root(),
        cbm_sys::vendor_root(),
    )
}

/// Stable Windows identity of one open directory object.
///
/// The server is deliberately `forbid(unsafe_code)`. This bridge already owns
/// the process's native/FFI boundary, so the Win32 handle calls live here and
/// callers receive a fully owned, safe value.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WindowsDirectoryIdentity {
    pub volume_serial: u64,
    pub file_id_128: [u8; 16],
    pub final_handle_path: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WindowsDirectoryIdentityError {
    pub step: &'static str,
    pub raw_os_error: Option<i32>,
    pub message: String,
}

/// Stable Windows identity and immutable metadata for one opened ordinary file.
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct WindowsFileIdentity {
    pub volume_serial: u64,
    pub file_id_128: [u8; 16],
    pub final_handle_path: String,
    pub bytes: u64,
    pub last_write_time: u64,
    pub file_attributes: u32,
}

impl fmt::Display for WindowsDirectoryIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "root identity step {:?} failed: {} (raw_os_error={:?})",
            self.step, self.message, self.raw_os_error
        )
    }
}

impl Error for WindowsDirectoryIdentityError {}

#[cfg(windows)]
fn windows_file_identity_from_open_file(
    path: &Path,
    file: &File,
) -> Result<WindowsFileIdentity, WindowsDirectoryIdentityError> {
    use std::os::windows::fs::MetadataExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_ID_INFO, FILE_NAME_NORMALIZED, FileIdInfo,
        GetFileInformationByHandleEx, GetFinalPathNameByHandleW, VOLUME_NAME_DOS,
    };

    let failure = |step, error: std::io::Error| WindowsDirectoryIdentityError {
        step,
        raw_os_error: error.raw_os_error(),
        message: format!("{}: {error}", path.display()),
    };
    let metadata = file
        .metadata()
        .map_err(|error| failure("file_metadata", error))?;
    if !metadata.is_file() {
        return Err(failure(
            "file_kind",
            std::io::Error::other("the worker executable path is not an ordinary file"),
        ));
    }
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(failure(
            "file_reparse",
            std::io::Error::other("the worker executable path is a reparse point"),
        ));
    }
    if metadata.len() == 0 {
        return Err(failure(
            "file_empty",
            std::io::Error::other("the worker executable file is empty"),
        ));
    }

    let handle = file.as_raw_handle();
    let mut file_id = FILE_ID_INFO::default();
    // SAFETY: `file` owns a live file handle and `file_id` is a correctly sized
    // writable output buffer. No borrowed value escapes this call.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&raw mut file_id).cast(),
            u32::try_from(std::mem::size_of::<FILE_ID_INFO>()).expect("FILE_ID_INFO fits u32"),
        )
    } == 0
    {
        return Err(failure("file_id_info", std::io::Error::last_os_error()));
    }
    let flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
    // SAFETY: the null buffer is the documented size query for the retained
    // handle and is not dereferenced.
    let required = unsafe { GetFinalPathNameByHandleW(handle, ptr::null_mut(), 0, flags) };
    if required == 0 {
        return Err(failure("final_path_size", std::io::Error::last_os_error()));
    }
    let mut buffer = vec![0_u16; required as usize + 1];
    let capacity = u32::try_from(buffer.len()).map_err(|_| {
        failure(
            "final_path_capacity",
            std::io::Error::other("final path buffer exceeds u32"),
        )
    })?;
    // SAFETY: the buffer is writable for `capacity` UTF-16 units and the file
    // handle remains live for the duration of the call.
    let written =
        unsafe { GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), capacity, flags) };
    if written == 0 || written as usize >= buffer.len() {
        return Err(failure("final_path_read", std::io::Error::last_os_error()));
    }
    let mut final_handle_path =
        String::from_utf16(&buffer[..written as usize]).map_err(|error| {
            failure(
                "final_path_utf16",
                std::io::Error::new(std::io::ErrorKind::InvalidData, error),
            )
        })?;
    if let Some(rest) = final_handle_path.strip_prefix(r"\\?\UNC\") {
        final_handle_path = format!(r"\\{rest}");
    } else if let Some(rest) = final_handle_path.strip_prefix(r"\\?\") {
        final_handle_path = rest.to_string();
    }
    Ok(WindowsFileIdentity {
        volume_serial: file_id.VolumeSerialNumber,
        file_id_128: file_id.FileId.Identifier,
        final_handle_path,
        bytes: metadata.len(),
        last_write_time: metadata.last_write_time(),
        file_attributes: metadata.file_attributes(),
    })
}

/// Open and independently identify one ordinary Windows file without retaining
/// the handle after this function returns.
#[cfg(windows)]
pub fn capture_windows_file_identity(
    path: &Path,
) -> Result<WindowsFileIdentity, WindowsDirectoryIdentityError> {
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    };

    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .open(path)
        .map_err(|error| WindowsDirectoryIdentityError {
            step: "open_file",
            raw_os_error: error.raw_os_error(),
            message: format!("{}: {error}", path.display()),
        })?;
    windows_file_identity_from_open_file(path, &file)
}

#[cfg(not(windows))]
pub fn capture_windows_file_identity(
    path: &Path,
) -> Result<WindowsFileIdentity, WindowsDirectoryIdentityError> {
    Err(WindowsDirectoryIdentityError {
        step: "platform",
        raw_os_error: None,
        message: format!(
            "{}: Windows file identity is unavailable outside the native Windows target",
            path.display()
        ),
    })
}

#[cfg(windows)]
pub fn capture_windows_directory_identity(
    path: &Path,
) -> Result<WindowsDirectoryIdentity, WindowsDirectoryIdentityError> {
    use std::os::windows::fs::OpenOptionsExt;
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_FLAG_BACKUP_SEMANTICS, FILE_ID_INFO, FILE_NAME_NORMALIZED, FILE_SHARE_DELETE,
        FILE_SHARE_READ, FILE_SHARE_WRITE, FileIdInfo, GetFileInformationByHandleEx,
        GetFinalPathNameByHandleW, VOLUME_NAME_DOS,
    };

    let failure = |step, error: std::io::Error| WindowsDirectoryIdentityError {
        step,
        raw_os_error: error.raw_os_error(),
        message: format!("{}: {error}", path.display()),
    };
    let file = OpenOptions::new()
        .read(true)
        .share_mode(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)
        .custom_flags(FILE_FLAG_BACKUP_SEMANTICS)
        .open(path)
        .map_err(|error| failure("open_directory", error))?;
    if !file
        .metadata()
        .map_err(|error| failure("directory_metadata", error))?
        .is_dir()
    {
        return Err(failure(
            "directory_kind",
            std::io::Error::other("the registered root path is not a directory"),
        ));
    }

    let handle = file.as_raw_handle();
    let mut file_id = FILE_ID_INFO::default();
    // SAFETY: `file` owns a live directory handle; `file_id` is a correctly
    // sized writable FILE_ID_INFO buffer and no borrowed value escapes.
    if unsafe {
        GetFileInformationByHandleEx(
            handle,
            FileIdInfo,
            (&raw mut file_id).cast(),
            u32::try_from(std::mem::size_of::<FILE_ID_INFO>()).expect("FILE_ID_INFO fits u32"),
        )
    } == 0
    {
        return Err(failure("file_id_info", std::io::Error::last_os_error()));
    }

    let flags = FILE_NAME_NORMALIZED | VOLUME_NAME_DOS;
    // SAFETY: a null/zero buffer is the documented size query for this live
    // handle and does not dereference the null pointer.
    let required = unsafe { GetFinalPathNameByHandleW(handle, ptr::null_mut(), 0, flags) };
    if required == 0 {
        return Err(failure("final_path_size", std::io::Error::last_os_error()));
    }
    let mut buffer = vec![0u16; required as usize + 1];
    let capacity = u32::try_from(buffer.len()).map_err(|_| {
        failure(
            "final_path_capacity",
            std::io::Error::other("final path buffer exceeds u32"),
        )
    })?;
    // SAFETY: `buffer` is writable for `capacity` UTF-16 units and the owned
    // directory handle remains live through the call.
    let written =
        unsafe { GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), capacity, flags) };
    if written == 0 || written as usize >= buffer.len() {
        return Err(failure("final_path_read", std::io::Error::last_os_error()));
    }
    let final_handle_path = String::from_utf16(&buffer[..written as usize]).map_err(|error| {
        failure(
            "final_path_utf16",
            std::io::Error::new(std::io::ErrorKind::InvalidData, error),
        )
    })?;
    Ok(WindowsDirectoryIdentity {
        volume_serial: file_id.VolumeSerialNumber,
        file_id_128: file_id.FileId.Identifier,
        final_handle_path,
    })
}

#[cfg(not(windows))]
pub fn capture_windows_directory_identity(
    path: &Path,
) -> Result<WindowsDirectoryIdentity, WindowsDirectoryIdentityError> {
    Err(WindowsDirectoryIdentityError {
        step: "platform",
        raw_os_error: None,
        message: format!(
            "{}: Windows root identity is unavailable outside the native Windows target",
            path.display()
        ),
    })
}

/// Byte capacity of a CBM store path.
///
/// `cbm_resolve_cache_dir` and `cbm_get_home_dir`
/// (`cbm/src/foundation/platform.c`) publish their result
/// from a `static char[CBM_SZ_1K]`, so a store path longer than this cannot be
/// represented by the library at all. Astrolabe's store-resolution edits
/// (`ASTRO_ENV_STORE`-guarded, in the owned
/// `cbm/src/foundation/platform.c`, #241) widen the
/// *environment* scratch buffers those resolvers used — a `char[CBM_SZ_256]`, an
/// artificial cut with no relation to what the library can hold, and one that
/// silently relocated the store for any Windows path over 255 bytes — up to the
/// same `CBM_SZ_1K`, and refuse anything longer with a named fault instead of
/// truncating it.
///
/// This is not a magic number: it is measured from the owned
/// `src/foundation/constants.h` enum and asserted against it by
/// `cbm_store_path_capacity_matches_vendor_constant`, and the C half asserts the
/// same equality at compile time in `patches/cbm/env_store_config.c`.
const CBM_STORE_PATH_CAPACITY: usize = 1024;

/// Drain the fail-closed store-configuration fault libcbm publishes (#241).
///
/// The C half records a `{code, message, remediation}` envelope whenever an
/// environment value it needs would have to be truncated, or whenever no store can
/// be resolved at all. Returning it here is what turns the vendored resolvers'
/// bare `NULL` — historically consumed as if it could not happen — into a labeled
/// refusal on the Rust side.
fn drain_cbm_env_fault() -> Option<BridgeError> {
    if let Err(error) = initialize_cbm_allocator() {
        return Some(error);
    }
    // SAFETY: the fault accessors return either NULL or a pointer into
    // process-lifetime static storage owned by libcbm; the strings are copied out
    // before the record is cleared.
    unsafe {
        let code = cbm_sys::cbm_astro_env_fault_code();
        if code.is_null() {
            return None;
        }
        let read = |ptr: *const c_char| {
            if ptr.is_null() {
                String::new()
            } else {
                CStr::from_ptr(ptr).to_string_lossy().into_owned()
            }
        };
        let code = read(code);
        let message = read(cbm_sys::cbm_astro_env_fault_message());
        let remediation = read(cbm_sys::cbm_astro_env_fault_remediation());
        cbm_sys::cbm_astro_env_fault_clear();
        Some(envelope(code, message, remediation))
    }
}

/// Drain a pending fault only when it names a variable the store path is built
/// from. A truncation fault against, say, `PATH` is real but must not condemn the
/// cache-directory resolution, which never reads `PATH`.
fn drain_cbm_store_fault() -> Option<BridgeError> {
    if let Err(error) = initialize_cbm_allocator() {
        return Some(error);
    }
    const STORE_VARS: [&CStr; 3] = [c"CBM_CACHE_DIR", c"HOME", c"USERPROFILE"];
    // SAFETY: cbm_astro_env_faulted_for reads the process-global fault record and
    // compares against the passed NUL-terminated name; no borrowed state escapes.
    let for_store = STORE_VARS
        .iter()
        .any(|name| unsafe { cbm_sys::cbm_astro_env_faulted_for(name.as_ptr()) } != 0);
    if for_store {
        drain_cbm_env_fault()
    } else {
        None
    }
}

/// Point libcbm at `path` for every subsequent store resolution (#240).
///
/// **This is the only runtime-safe way to relocate the CBM store.** A
/// `std::env::set_var("CBM_CACHE_DIR", ...)` does *not* work: on Windows Rust's
/// `set_var` writes the Win32 environment block through `SetEnvironmentVariableW`,
/// while libcbm's `cbm_safe_getenv` walks the C runtime's `environ` array. Those
/// are two separate stores, synchronised by Windows only for the environment a
/// process *inherits* — Microsoft documents `getenv` as operating "only on the data
/// structures accessible to the run-time library and not on the environment
/// 'segment' created for the process by the operating system". So a runtime
/// `set_var` is simply invisible to libcbm, which then resolves the store from
/// `$HOME` and reports no error at all: a silent fallback, and the mechanism by
/// which #194's cache leak reappears.
///
/// The durable contract is to stop using the environment as an IPC channel and pass
/// the configuration across the FFI boundary as a parameter, which is what this
/// function does. `scripts/check-cbm-env-contract.py` fails the build closed if a
/// bare `set_var` for any libcbm-consumed variable is reintroduced.
///
/// Returns the store directory, created if absent. Fails closed with the C half's
/// `{code, message, remediation}` envelope.
pub fn set_cbm_cache_dir(path: &std::path::Path) -> Result<PathBuf, BridgeError> {
    let raw = path.to_str().ok_or_else(|| {
        envelope(
            "ASTRO_CBM_CACHE_DIR_NOT_UTF8",
            format!("the CBM store path {path:?} is not valid UTF-8"),
            "Point the CBM store at a UTF-8 absolute path.",
        )
    })?;
    // The same three silent degradations validate_cbm_store_env refuses for an
    // inherited value are refused for an explicitly configured one: an empty path
    // falls through to the home store, a relative one resolves against whatever cwd
    // the process happens to have, and an over-long one cannot be represented.
    validate_cbm_store_env(Some(raw), None, None)?;

    initialize_cbm_allocator()?;
    let c_path = CString::new(raw)?;
    // SAFETY: cbm_astro_set_cache_dir copies the path into process-global storage
    // owned by libcbm; the CString outlives the call.
    let rc = unsafe { cbm_sys::cbm_astro_set_cache_dir(c_path.as_ptr()) };
    if rc != 0 {
        return Err(drain_cbm_env_fault().unwrap_or_else(|| {
            envelope(
                "ASTRO_CBM_CACHE_DIR_REJECTED",
                format!("libcbm refused the store path {raw} with status {rc}"),
                "Point the CBM store at a writable absolute path.",
            )
        }));
    }

    // Independent read of the source of truth: ask libcbm's OWN resolver where the
    // store is now. A return code from the setter is an echo; this is the value
    // every indexing path inside libcbm will actually use.
    let resolved = cbm_cache_dir()?;
    let requested = std::path::Path::new(raw);
    if resolved != requested {
        return Err(envelope(
            "ASTRO_CBM_CACHE_DIR_NOT_HONOURED",
            format!(
                "libcbm resolved its store to {} after being configured with {}",
                resolved.display(),
                requested.display()
            ),
            "This is a libcbm store-overlay defect; file an issue with both paths.",
        ));
    }
    Ok(resolved)
}

/// Drop any explicit store override, restoring `CBM_CACHE_DIR`/`$HOME` precedence.
pub fn clear_cbm_cache_dir() -> Result<(), BridgeError> {
    initialize_cbm_allocator()?;
    // SAFETY: process-global reset of libcbm's override buffer; no borrowed inputs.
    unsafe { cbm_sys::cbm_astro_clear_cache_dir() };
    Ok(())
}

/// Fail-closed validation of the environment that decides where the CBM project
/// store lives (#194/#232).
///
/// A project is "registered" in CBM purely by the presence of `<slug>.db` in the
/// resolved cache directory, so a misread of this environment silently relocates
/// (or truncates) every index the host writes. The vendored resolver degrades
/// quietly in three ways — an empty `CBM_CACHE_DIR` falls through to `$HOME`, a
/// relative one resolves against whatever the process cwd happens to be, and an
/// over-long one is truncated mid-path. Astrolabe refuses all three at its own
/// door instead, because every server store path resolves through
/// [`cbm_cache_dir`].
fn validate_cbm_store_env(
    cache_dir: Option<&str>,
    home: Option<&str>,
    user_profile: Option<&str>,
) -> Result<(), BridgeError> {
    if let Some(raw) = cache_dir {
        if raw.is_empty() {
            return Err(envelope(
                "ASTRO_CBM_CACHE_DIR_EMPTY",
                "CBM_CACHE_DIR is set but empty; CBM would silently fall back to the home store",
                "Unset CBM_CACHE_DIR to use the default store, or set it to an absolute path.",
            ));
        }
        if raw.len() >= CBM_STORE_PATH_CAPACITY {
            return Err(envelope(
                "ASTRO_CBM_CACHE_DIR_TRUNCATED",
                format!(
                    "CBM_CACHE_DIR is {} bytes; CBM publishes resolved store paths from a \
                     {}-byte buffer and cannot represent it",
                    raw.len(),
                    CBM_STORE_PATH_CAPACITY
                ),
                format!(
                    "Point CBM_CACHE_DIR at an absolute path shorter than {CBM_STORE_PATH_CAPACITY} bytes."
                ),
            ));
        }
        if !std::path::Path::new(raw).is_absolute() {
            return Err(envelope(
                "ASTRO_CBM_CACHE_DIR_RELATIVE",
                format!(
                    "CBM_CACHE_DIR must be an absolute path; {raw:?} would resolve against the \
                     process working directory and scatter the project store"
                ),
                "Set CBM_CACHE_DIR to an absolute path (or unset it to use the default store).",
            ));
        }
        return Ok(());
    }

    // No override: CBM falls back to <home>/.cache/codebase-memory-mcp, reading
    // HOME first and USERPROFILE second (platform.c:327). Whichever it would use
    // is subject to the same truncation.
    let home = home
        .filter(|value| !value.is_empty())
        .or(user_profile.filter(|value| !value.is_empty()));
    if let Some(home) = home
        && home.len() >= CBM_STORE_PATH_CAPACITY
    {
        return Err(envelope(
            "ASTRO_CBM_HOME_TRUNCATED",
            format!(
                "HOME/USERPROFILE is {} bytes; CBM publishes resolved store paths from a \
                 {}-byte buffer and cannot represent the home store path",
                home.len(),
                CBM_STORE_PATH_CAPACITY
            ),
            format!(
                "Set CBM_CACHE_DIR to an absolute path shorter than {CBM_STORE_PATH_CAPACITY} bytes."
            ),
        ));
    }
    Ok(())
}

pub fn cbm_cache_dir() -> Result<PathBuf, BridgeError> {
    validate_cbm_store_env(
        std::env::var("CBM_CACHE_DIR").ok().as_deref(),
        std::env::var("HOME").ok().as_deref(),
        std::env::var("USERPROFILE").ok().as_deref(),
    )?;

    initialize_cbm_allocator()?;
    let ptr = unsafe { cbm_sys::cbm_resolve_cache_dir() };
    if ptr.is_null() {
        // #241: the C half publishes a {code, message, remediation} envelope naming
        // exactly why it refused (a truncated value, or no store at all). Surface
        // that rather than a generic guess.
        return Err(drain_cbm_env_fault().unwrap_or_else(|| {
            envelope(
                "ASTRO_CBM_CACHE_DIR",
                "CBM could not resolve its cache directory",
                "Set CBM_CACHE_DIR or HOME/LOCALAPPDATA to a writable directory.",
            )
        }));
    }
    // A non-NULL resolve with a pending fault against one of the variables the store
    // is built from means CBM could not read that value whole. Refuse rather than
    // index into a path derived from a partially-read environment. Faults against
    // unrelated variables (a huge PATH, say) are left on the record for their own
    // consumer; they do not condemn the store.
    if let Some(fault) = drain_cbm_store_fault() {
        return Err(fault);
    }
    let resolved = PathBuf::from(unsafe { CStr::from_ptr(ptr) }.to_str()?);

    // The store must be a usable directory before anything indexes into it. CBM
    // creates it on first write; doing it here turns "your db went somewhere
    // surprising" into a named, actionable failure at the door.
    if resolved.exists() && !resolved.is_dir() {
        return Err(envelope(
            "ASTRO_CBM_CACHE_DIR_NOT_A_DIRECTORY",
            format!(
                "the resolved CBM store {} exists but is not a directory",
                resolved.display()
            ),
            "Point CBM_CACHE_DIR at a directory (or remove the conflicting file).",
        ));
    }
    if let Err(error) = std::fs::create_dir_all(&resolved) {
        return Err(envelope(
            "ASTRO_CBM_CACHE_DIR_UNUSABLE",
            format!(
                "the resolved CBM store {} cannot be created or opened: {error}",
                resolved.display()
            ),
            "Point CBM_CACHE_DIR at a writable absolute path.",
        ));
    }
    Ok(resolved)
}

/// Parses a persisted libcbm boolean through the native parser shared with the
/// standalone watch-registration path.
///
/// This deliberately has no default: callers decide whether an absent row has
/// a documented default before invoking it, while every present malformed row
/// is returned as a named error.
pub fn parse_cbm_config_bool_strict(value: &str) -> Result<bool, BridgeError> {
    initialize_cbm_allocator()?;
    let value_c = CString::new(value)?;
    let mut parsed = false;
    // SAFETY: value_c is a live NUL-terminated string and parsed is a live bool
    // output for the duration of the call.
    let status = unsafe { cbm_sys::cbm_config_parse_bool_strict(value_c.as_ptr(), &mut parsed) };
    if status == 0 {
        Ok(parsed)
    } else {
        Err(envelope(
            "ASTRO_CONFIG_BOOL_INVALID",
            format!("persisted config value {value:?} is not one of true, 1, on, false, 0, or off"),
            "Repair or remove the exact malformed config row before retrying; Astrolabe will not substitute a default for present invalid state.",
        ))
    }
}

pub fn cbm_memory_budget_bytes() -> Result<usize, BridgeError> {
    initialize_cbm_allocator()?;
    // SAFETY: these CBM functions are process-global budget initializers/readers
    // with no borrowed inputs. cbm_mem_init is idempotent.
    unsafe {
        let info = cbm_sys::cbm_system_info();
        let ram_fraction = cbm_sys::cbm_mem_ram_fraction_for_total(info.total_ram);
        cbm_sys::cbm_mem_init(ram_fraction);
        Ok(cbm_sys::cbm_mem_budget())
    }
}

pub fn cbm_project_name_from_path(path: &str) -> Result<String, BridgeError> {
    initialize_cbm_allocator()?;
    let path = CString::new(path)?;
    let ptr = unsafe { cbm_sys::cbm_project_name_from_path(path.as_ptr()) };
    unsafe { take_c_string(ptr) }
}

/// Print per-tool `--help` for a CLI surface (#416) by delegating to the single
/// shared C formatter `cbm_cli_print_tool_help_prog`, so the help text and the
/// tool's JSON argument schema have one source of truth across both the
/// standalone cbm binary and the astrolabe host CLI. The C function writes the
/// help directly to this process's stdout, using `prog` as the program name in
/// the Usage lines. Returns `Ok(true)` when the tool is known (help printed),
/// `Ok(false)` when the tool name is unknown (nothing was printed) so the caller
/// can fail closed with a labeled error.
/// Whether `pid` currently names a live process. Gates the archaeology
/// orphan-worktree sweep (#427): a definitively-absent PID is dead (its crashed
/// worktree is safe to remove); every ambiguous outcome — access-denied,
/// transient failure, or a non-Windows port target — is treated as ALIVE so a
/// possibly-live worktree is never swept (fail-closed toward preservation).
/// PID recycling can at worst leave one orphan uncollected; it can never cause
/// a wrongful deletion. Lives here because the server crate forbids unsafe code
/// and this crate owns all FFI.
#[cfg(windows)]
pub fn process_is_alive(pid: u32) -> bool {
    use std::ffi::c_void;
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> *mut c_void;
        fn CloseHandle(handle: *mut c_void) -> i32;
        fn GetLastError() -> u32;
    }
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x1000;
    const ERROR_INVALID_PARAMETER: u32 = 87;
    // SAFETY: OpenProcess takes only scalars and returns a handle or null; nothing
    // is dereferenced. A non-null handle is closed exactly once via CloseHandle.
    let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if handle.is_null() {
        // SAFETY: GetLastError reads thread-local error state, no preconditions.
        let code = unsafe { GetLastError() };
        // Only "no such PID" proves death; any other failure stays conservatively alive.
        return code != ERROR_INVALID_PARAMETER;
    }
    // SAFETY: handle is a valid, open process handle from the OpenProcess above.
    unsafe { CloseHandle(handle) };
    true
}

/// Port-deferred (`ASTRO_PORT_PHASE`): no portable liveness probe is wired yet,
/// so every PID is treated as alive — the archaeology sweep then removes nothing
/// rather than risk deleting a live worktree. Never reached on the shipping
/// Windows target.
#[cfg(not(windows))]
pub fn process_is_alive(_pid: u32) -> bool {
    true
}

pub fn cbm_print_tool_help(prog: &str, tool_name: &str) -> Result<bool, BridgeError> {
    initialize_cbm_allocator()?;
    let prog = CString::new(prog)?;
    let tool_name = CString::new(tool_name)?;
    // SAFETY: both CStrings outlive the call; the C function only reads the two
    // NUL-terminated strings and writes formatted help to stdout, returning 0
    // when the tool is known and non-zero (printing nothing) when it is not.
    let rc = unsafe { cbm_sys::cbm_cli_print_tool_help_prog(prog.as_ptr(), tool_name.as_ptr()) };
    // The C formatter flushes stdout before returning, so the help is emitted
    // regardless of how the process later exits.
    Ok(rc == 0)
}

static CBM_JSON_LOG_MODE: AtomicBool = AtomicBool::new(false);
static CBM_LOG_CONFIGURATION: OnceLock<Result<bool, BridgeError>> = OnceLock::new();

/// Admit the process-wide libcbm log configuration exactly once.
///
/// libcbm performs a transactional parse: absence selects text, exact
/// case-insensitive `text`/`json` selects that format, and any other present
/// byte sequence returns without changing either the current level or format.
/// The Rust boundary retains exact byte length and hex so empty, whitespace,
/// and non-UTF-8 values remain distinguishable in the refusal.
pub fn initialize_cbm_log_configuration() -> Result<bool, BridgeError> {
    CBM_LOG_CONFIGURATION
        .get_or_init(|| {
            initialize_cbm_allocator()?;
            // SAFETY: startup calls this before creating CBM worker threads or
            // mutating the environment. A non-NULL result points into the
            // process environment and is copied before this function returns.
            let invalid = unsafe { cbm_sys::cbm_log_init_from_env() };
            if !invalid.is_null() {
                // SAFETY: libcbm returns the exact NUL-terminated getenv value.
                let value = unsafe { CStr::from_ptr(invalid) }.to_bytes();
                const HEX: &[u8; 16] = b"0123456789abcdef";
                let mut value_hex = String::with_capacity(value.len().saturating_mul(2));
                for byte in value {
                    value_hex.push(HEX[(byte >> 4) as usize] as char);
                    value_hex.push(HEX[(byte & 0x0f) as usize] as char);
                }
                return Err(envelope(
                    "CBM_LOG_FORMAT_INVALID",
                    format!(
                        "CBM_LOG_FORMAT must be exactly text or json (case-insensitive) when present; value_bytes={}, value_hex={value_hex}",
                        value.len()
                    ),
                    "Set CBM_LOG_FORMAT to text or json, or remove it to select the text default.",
                ));
            }
            // SAFETY: successful admission committed one of the two declared
            // CBMLogFormat values under the native log mutex.
            Ok(unsafe {
                cbm_sys::cbm_log_get_format() == cbm_sys::CBMLogFormat_CBM_LOG_FORMAT_JSON
            })
        })
        .clone()
}

pub fn route_cbm_logs_to_tracing() -> Result<bool, BridgeError> {
    let json_mode = initialize_cbm_log_configuration()?;
    // SAFETY: the callback is a static extern function and remains valid for
    // the process lifetime. CBM stores only the function pointer.
    unsafe {
        CBM_JSON_LOG_MODE.store(json_mode, Ordering::Release);
        cbm_sys::cbm_log_set_sink_ex(
            Some(cbm_log_tracing_sink),
            cbm_sys::CBMLogSinkMode_CBM_LOG_SINK_REPLACE,
        );
    }
    Ok(json_mode)
}

static CBM_PROFILE_ACTIVE: OnceLock<bool> = OnceLock::new();

/// Initializes libcbm's inherited profile mode exactly once and returns its
/// process-global verdict.
///
/// The host needs this before constructing its Rust tracing subscriber: every
/// native profile record is INFO, so a CLI WARN subscriber would discard the
/// events before the supervisor can retain them. The environment contract stays
/// native-owned; Rust consumes only libcbm's initialized verdict (#767).
pub fn initialize_cbm_profile_mode() -> Result<bool, BridgeError> {
    initialize_cbm_allocator()?;
    Ok(*CBM_PROFILE_ACTIVE.get_or_init(|| unsafe {
        cbm_sys::cbm_profile_init();
        cbm_sys::cbm_profile_is_active()
    }))
}

/// How libcbm's own logging is initialized for this host process (#392).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CbmLogMode {
    /// Server (no-arg) dispatch: leave libcbm at its env/default level (INFO) so
    /// operators keep the full server log stream on stderr.
    Default,
    /// `cli <tool>` dispatch: raise the libcbm log floor so `mem.init`/`vmem.init`
    /// INFO lines never reach stderr — CLI stderr is reserved for warn/error, so
    /// the supported `--args-file`/stdin forms emit empty stderr. The exact floor
    /// is the registry-declared `cli_stderr_log_level_floor` knob.
    CliWarnFloor,
    /// Hook-augment dispatch: fully silence libcbm (level NONE + silent sink) so a
    /// short-budget hook never writes to stderr at all.
    Silent,
}

const ASTRO_INDEX_WORKER_CAPABILITY_ARG: &str = "__astrolabe-index-worker-capability-v1";
const ASTRO_INDEX_WORKER_CAPABILITY_SCHEMA: &str = "astrolabe.index-worker-capability.v3";
const ASTRO_INDEX_WORKER_ARGV_SCHEMA: &str = "astrolabe.index-worker-argv.v2";
const ASTRO_INDEX_WORKER_PROGRESS_SCHEMA: &str = "cbm.worker-progress.v1";
const ASTRO_WORKER_SOURCE_GENERATION_SCHEMA: &str = "astrolabe.worker-source-generation.v1";
static WORKER_CAPABILITY_CHALLENGE_ORDINAL: AtomicU64 = AtomicU64::new(0);

// A Windows extended path contains at most 32,767 UTF-16 units. JSON escaping
// can expand one unit to at most six ASCII bytes; the fixed capability fields
// fit inside the additional 16 KiB. This is a protocol-shape ceiling, not a
// measured runtime budget.
#[cfg(windows)]
const WORKER_CAPABILITY_OUTPUT_MAX_BYTES: usize = 32_767 * 6 + 16 * 1024;

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CbmWorkerCapabilityReceipt {
    pub schema: String,
    pub challenge: String,
    pub worker_argv_schema: String,
    pub progress_schema: String,
    pub progress_schema_version: u64,
    pub worker_argv_template: Vec<String>,
    pub worker_cache_arg: String,
    pub transition_grant_arg: String,
    pub package_version: String,
    pub source_generation_schema: String,
    pub source_generation_sha256: String,
    pub artifact_identity: WindowsFileIdentity,
}

struct ExternalWorkerLease {
    file: File,
    identity: WindowsFileIdentity,
}

/// Independent parent-side evidence that the private capability process began
/// as one detached, suspended, atomically Job-owned generation, was resumed
/// exactly once, reached bounded EOF, and left the same lifetime accounting
/// with the Job observed empty twice before its receipt was accepted.
#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CbmWorkerCapabilityObservation {
    pub child_pid: u32,
    pub primary_thread_id: u32,
    pub resume_previous_suspend_count: u32,
    pub timeout_ms: u32,
    pub elapsed_micros: u64,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub job_empty_readbacks: u32,
    pub job_pre_spawn_snapshot: CbmWorkerCapabilityJobSnapshot,
    pub job_suspended_snapshot: CbmWorkerCapabilityJobSnapshot,
    pub job_terminal_snapshot: CbmWorkerCapabilityJobSnapshot,
}

/// Exact parent-side bracketed Job accounting and PID-list state at one
/// capability lifecycle boundary.
#[derive(Debug, Clone, Copy, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CbmWorkerCapabilityJobSnapshot {
    pub accounting_before_total_processes: u32,
    pub accounting_before_active_processes: u32,
    pub accounting_before_total_terminated_processes: u32,
    pub total_processes: u32,
    pub active_processes: u32,
    pub total_terminated_processes: u32,
    pub assigned_processes: u32,
    pub listed_processes: u32,
    pub listed_process_id: Option<u32>,
}

struct BoundedCapabilityProcess {
    output: Output,
    observation: CbmWorkerCapabilityObservation,
}

#[cfg(windows)]
mod capability_process {
    use super::*;
    use std::ffi::OsStr;
    use std::mem::{offset_of, size_of};
    use std::os::windows::ffi::OsStrExt;
    use std::os::windows::io::{AsRawHandle, FromRawHandle};
    use std::os::windows::process::ExitStatusExt;
    use std::sync::mpsc::{self, Receiver, RecvTimeoutError, TryRecvError};
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{
        CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, ERROR_INSUFFICIENT_BUFFER,
        GetLastError, HANDLE, WAIT_FAILED, WAIT_OBJECT_0, WAIT_TIMEOUT,
    };
    use windows_sys::Win32::System::JobObjects::{
        CreateJobObjectW, IsProcessInJob, JOB_OBJECT_LIMIT_ACTIVE_PROCESS,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
        JOBOBJECT_BASIC_PROCESS_ID_LIST, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JobObjectBasicAccountingInformation, JobObjectBasicProcessIdList,
        JobObjectExtendedLimitInformation, QueryInformationJobObject, SetInformationJobObject,
        TerminateJobObject,
    };
    use windows_sys::Win32::System::Pipes::CreatePipe;
    use windows_sys::Win32::System::Threading::{
        CREATE_SUSPENDED, CreateProcessW, DETACHED_PROCESS, DeleteProcThreadAttributeList,
        EXTENDED_STARTUPINFO_PRESENT, GetCurrentProcess, GetExitCodeProcess,
        InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
        PROC_THREAD_ATTRIBUTE_HANDLE_LIST, PROC_THREAD_ATTRIBUTE_JOB_LIST, PROCESS_INFORMATION,
        ResumeThread, STARTF_USESTDHANDLES, STARTUPINFOEXW, STARTUPINFOW,
        UpdateProcThreadAttribute, WaitForSingleObject,
    };

    const PROCESS_ATTRIBUTE_COUNT: u32 = 2;
    const MAX_WINDOWS_COMMAND_LINE_UNITS: usize = 32_767;
    const REQUIRED_JOB_LIMITS: u32 =
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    const REQUIRED_ACTIVE_PROCESS_LIMIT: u32 = 1;
    const REQUIRED_EMPTY_READBACKS: u32 = 2;
    const CLEANUP_RESERVE_DIVISOR: u32 = 4;
    const CAPABILITY_TERMINATION_EXIT_CODE: u32 = 0xA57C_0001;
    const PROCESS_LIST_OFFSET: usize = offset_of!(JOBOBJECT_BASIC_PROCESS_ID_LIST, ProcessIdList);

    #[derive(Debug)]
    struct PipeCapture {
        bytes: Vec<u8>,
        overflow: bool,
        total_bytes: u64,
    }

    type CapabilityPipeRead = std::io::Result<PipeCapture>;

    struct CapabilityReader {
        label: &'static str,
        receiver: Receiver<CapabilityPipeRead>,
    }

    impl CapabilityReader {
        fn spawn(label: &'static str, file: File) -> Result<Self, BridgeError> {
            let (sender, receiver) = mpsc::sync_channel(1);
            let thread_name = format!("cbm-capability-{label}");
            let reader = thread::Builder::new()
                .name(thread_name)
                .spawn(move || {
                    let result = read_bounded_pipe(file);
                    let _ = sender.send(result);
                })
                .map_err(|error| {
                    envelope(
                        format!(
                            "ASTRO_CBM_WORKER_CAPABILITY_{}_READER_SPAWN_FAILED",
                            label.to_ascii_uppercase()
                        ),
                        format!("capability {label} reader could not start: {error}"),
                        "Stop startup and inspect native thread creation; never run a capability process with an unconsumed pipe.",
                    )
                })?;
            // The result channel, not JoinHandle::join, is the bounded terminal
            // protocol. A panicking reader disconnects the channel; no caller
            // can acquire an unbounded thread-join tail after its deadline.
            drop(reader);
            Ok(Self { label, receiver })
        }

        fn finish(self, deadline: Instant) -> Result<PipeCapture, String> {
            let received = match deadline.checked_duration_since(Instant::now()) {
                Some(remaining) if !remaining.is_zero() => self
                    .receiver
                    .recv_timeout(remaining)
                    .map_err(|error| match error {
                        RecvTimeoutError::Timeout => format!(
                            "{} reader did not publish EOF before its deadline",
                            self.label
                        ),
                        RecvTimeoutError::Disconnected => {
                            format!("{} reader terminated without a result", self.label)
                        }
                    }),
                _ => self.receiver.try_recv().map_err(|error| match error {
                    TryRecvError::Empty => {
                        format!("{} reader deadline expired before EOF", self.label)
                    }
                    TryRecvError::Disconnected => {
                        format!("{} reader terminated without a result", self.label)
                    }
                }),
            }?;
            received.map_err(|error| format!("{} pipe read failed: {error}", self.label))
        }
    }

    #[derive(Default)]
    struct CapabilityReaders {
        stdout: Option<CapabilityReader>,
        stderr: Option<CapabilityReader>,
    }

    impl CapabilityReaders {
        fn finish(
            &mut self,
            deadline: Instant,
        ) -> (Result<PipeCapture, String>, Result<PipeCapture, String>) {
            let stdout = self
                .stdout
                .take()
                .ok_or_else(|| "stdout reader was not retained".to_string())
                .and_then(|reader| reader.finish(deadline));
            let stderr = self
                .stderr
                .take()
                .ok_or_else(|| "stderr reader was not retained".to_string())
                .and_then(|reader| reader.finish(deadline));
            (stdout, stderr)
        }
    }

    fn pipe_result_summary(result: &Result<PipeCapture, String>) -> String {
        match result {
            Ok(capture) => format!(
                "ok(retained_bytes={}, total_bytes={}, overflow={})",
                capture.bytes.len(),
                capture.total_bytes,
                capture.overflow
            ),
            Err(error) => format!("error({error})"),
        }
    }

    struct OwnedKernelHandle(HANDLE);

    impl OwnedKernelHandle {
        fn new(handle: HANDLE) -> Option<Self> {
            (!handle.is_null()).then_some(Self(handle))
        }

        fn raw(&self) -> HANDLE {
            self.0
        }

        fn into_raw(self) -> HANDLE {
            let handle = self.0;
            std::mem::forget(self);
            handle
        }

        fn close(self) -> Result<(), (Self, u32)> {
            // SAFETY: `self` uniquely owns this exact non-null handle. A
            // successful close consumes that ownership and forgets the guard so
            // Drop cannot close it again. A failed close returns the still-owned
            // guard with the immediately captured thread-local error.
            if unsafe { CloseHandle(self.0) } != 0 {
                std::mem::forget(self);
                Ok(())
            } else {
                let os_code = unsafe { GetLastError() };
                Err((self, os_code))
            }
        }
    }

    impl Drop for OwnedKernelHandle {
        fn drop(&mut self) {
            // SAFETY: this guard uniquely owns one non-null kernel handle.
            unsafe { CloseHandle(self.0) };
        }
    }

    struct ProcThreadAttributeList {
        buffer: Vec<usize>,
    }

    impl ProcThreadAttributeList {
        fn new() -> Result<Self, BridgeError> {
            let mut byte_len = 0_usize;
            // SAFETY: the documented sizing call writes only the required byte
            // length when passed a null attribute-list pointer.
            let sized = unsafe {
                InitializeProcThreadAttributeList(
                    std::ptr::null_mut(),
                    PROCESS_ATTRIBUTE_COUNT,
                    0,
                    &mut byte_len,
                )
            };
            // SAFETY: this read immediately follows the sizing call.
            let size_error = unsafe { GetLastError() };
            if sized != 0 || size_error != ERROR_INSUFFICIENT_BUFFER || byte_len == 0 {
                return Err(win32_failure(
                    "ASTRO_CBM_WORKER_CAPABILITY_ATTRIBUTE_LIST_FAILED",
                    format!(
                        "capability process attribute-list sizing returned success={sized}, bytes={byte_len}"
                    ),
                    size_error,
                    "Inspect the Windows extended-startup attribute-list contract; do not launch an unbound capability process.",
                ));
            }
            let words = byte_len.div_ceil(size_of::<usize>());
            let mut buffer = Vec::new();
            buffer.try_reserve_exact(words).map_err(|error| {
                envelope(
                    "ASTRO_CBM_WORKER_CAPABILITY_ATTRIBUTE_LIST_FAILED",
                    format!(
                        "could not reserve {byte_len} bytes for capability process attributes: {error}"
                    ),
                    "Stop startup and inspect memory pressure; do not launch an unbound capability process.",
                )
            })?;
            buffer.resize(words, 0);
            let list = buffer.as_mut_ptr().cast();
            // SAFETY: the aligned buffer has at least the size returned by the
            // sizing call and remains owned by this guard.
            if unsafe {
                InitializeProcThreadAttributeList(list, PROCESS_ATTRIBUTE_COUNT, 0, &mut byte_len)
            } == 0
            {
                return Err(last_win32_failure(
                    "ASTRO_CBM_WORKER_CAPABILITY_ATTRIBUTE_LIST_FAILED",
                    "could not initialize the capability process attribute list",
                    "Inspect the Windows extended-startup attribute-list contract; do not launch an unbound capability process.",
                ));
            }
            Ok(Self { buffer })
        }

        fn raw(&self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
            self.buffer.as_ptr().cast_mut().cast()
        }

        fn update_handles(
            &mut self,
            attribute: usize,
            handles: &[HANDLE],
            label: &str,
        ) -> Result<(), BridgeError> {
            if handles.is_empty() || handles.iter().any(|handle| handle.is_null()) {
                return Err(envelope(
                    "ASTRO_CBM_WORKER_CAPABILITY_ATTRIBUTE_LIST_FAILED",
                    format!("the capability {label} is empty or contains a null handle"),
                    "Stop startup and inspect process-handle construction; do not launch an unbound capability process.",
                ));
            }
            let byte_len = handles
                .len()
                .checked_mul(size_of::<HANDLE>())
                .ok_or_else(|| {
                    envelope(
                        "ASTRO_CBM_WORKER_CAPABILITY_ATTRIBUTE_LIST_FAILED",
                        format!("the capability {label} byte length overflowed"),
                        "Stop startup and inspect process-handle construction; do not launch an unbound capability process.",
                    )
                })?;
            // SAFETY: the initialized list and handle array remain live through
            // CreateProcessW, and the exact handle-array byte length is passed.
            if unsafe {
                UpdateProcThreadAttribute(
                    self.raw(),
                    0,
                    attribute,
                    handles.as_ptr().cast(),
                    byte_len,
                    std::ptr::null_mut(),
                    std::ptr::null(),
                )
            } == 0
            {
                return Err(last_win32_failure(
                    "ASTRO_CBM_WORKER_CAPABILITY_ATTRIBUTE_LIST_FAILED",
                    format!("could not apply the capability {label}"),
                    "Inspect the Windows extended-startup handle-list contract; do not launch an unbound capability process.",
                ));
            }
            Ok(())
        }
    }

    impl Drop for ProcThreadAttributeList {
        fn drop(&mut self) {
            // SAFETY: the buffer contains one successfully initialized list.
            unsafe { DeleteProcThreadAttributeList(self.raw()) };
        }
    }

    struct CapabilityJob {
        handle: OwnedKernelHandle,
    }

    impl CapabilityJob {
        fn create() -> Result<Self, BridgeError> {
            // SAFETY: null attributes and name request a private unnamed Job.
            let handle = unsafe { CreateJobObjectW(std::ptr::null(), std::ptr::null()) };
            let handle = OwnedKernelHandle::new(handle).ok_or_else(|| {
                last_win32_failure(
                    "ASTRO_CBM_WORKER_CAPABILITY_JOB_CREATE_FAILED",
                    "could not create the private capability Job Object",
                    "Inspect Windows Job Object creation; do not run a capability outside an owned kill-on-close Job.",
                )
            })?;
            let job = Self { handle };
            let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
            limits.BasicLimitInformation.LimitFlags = REQUIRED_JOB_LIMITS;
            limits.BasicLimitInformation.ActiveProcessLimit = REQUIRED_ACTIVE_PROCESS_LIMIT;
            // SAFETY: the Job handle is live and `limits` is initialized for
            // its exact structure size.
            if unsafe {
                SetInformationJobObject(
                    job.handle.raw(),
                    JobObjectExtendedLimitInformation,
                    std::ptr::from_ref(&limits).cast(),
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                )
            } == 0
            {
                return Err(last_win32_failure(
                    "ASTRO_CBM_WORKER_CAPABILITY_JOB_CONFIGURE_FAILED",
                    "could not configure ACTIVE_PROCESS=1 and KILL_ON_JOB_CLOSE for the capability Job Object",
                    "Inspect Windows Job Object policy; do not run a capability without the exact cohort limits.",
                ));
            }
            let observed = query_job_limits(job.handle.raw())?;
            if observed.BasicLimitInformation.LimitFlags != REQUIRED_JOB_LIMITS
                || observed.BasicLimitInformation.ActiveProcessLimit
                    != REQUIRED_ACTIVE_PROCESS_LIMIT
            {
                return Err(envelope(
                    "ASTRO_CBM_WORKER_CAPABILITY_JOB_LIMIT_READBACK_MISMATCH",
                    format!(
                        "the capability Job readback was flags={:#x}, active_process_limit={}, expected flags={REQUIRED_JOB_LIMITS:#x}, active_process_limit={REQUIRED_ACTIVE_PROCESS_LIMIT}",
                        observed.BasicLimitInformation.LimitFlags,
                        observed.BasicLimitInformation.ActiveProcessLimit
                    ),
                    "Stop startup and inspect host Job Object policy; never accept a capability whose exact kill and process-count limits were not read back.",
                ));
            }
            Ok(job)
        }

        fn raw(&self) -> HANDLE {
            self.handle.raw()
        }
    }

    struct PipePair {
        reader: File,
        child_writer: OwnedKernelHandle,
    }

    fn create_pipe(label: &str) -> Result<PipePair, BridgeError> {
        let mut read_handle = std::ptr::null_mut();
        let mut write_handle = std::ptr::null_mut();
        // SAFETY: both output pointers are writable. Null security attributes
        // make both initial handles non-inheritable.
        let created =
            unsafe { CreatePipe(&mut read_handle, &mut write_handle, std::ptr::null(), 0) };
        // Capture the error before closing any partial handles.
        let os_code = (created == 0).then(|| unsafe { GetLastError() });
        let read_handle = OwnedKernelHandle::new(read_handle);
        let write_handle = OwnedKernelHandle::new(write_handle);
        if let Some(os_code) = os_code {
            return Err(win32_failure(
                "ASTRO_CBM_WORKER_CAPABILITY_PIPE_CREATE_FAILED",
                format!("could not create the capability {label} pipe"),
                os_code,
                "Inspect Windows anonymous-pipe creation; do not launch a capability without independently drained output.",
            ));
        }
        let read_handle = read_handle.ok_or_else(|| {
            envelope(
                "ASTRO_CBM_WORKER_CAPABILITY_PIPE_CREATE_FAILED",
                format!("CreatePipe returned a null capability {label} read handle"),
                "Stop startup and inspect Windows anonymous-pipe creation; do not launch a capability without independently drained output.",
            )
        })?;
        let write_handle = write_handle.ok_or_else(|| {
            envelope(
                "ASTRO_CBM_WORKER_CAPABILITY_PIPE_CREATE_FAILED",
                format!("CreatePipe returned a null capability {label} write handle"),
                "Stop startup and inspect Windows anonymous-pipe creation; do not launch a capability without independently drained output.",
            )
        })?;
        let child_writer = duplicate_inheritable_handle(write_handle.raw(), label)?;
        drop(write_handle);
        // SAFETY: ownership of this unique pipe handle moves into `File`.
        let reader = unsafe { File::from_raw_handle(read_handle.into_raw()) };
        Ok(PipePair {
            reader,
            child_writer,
        })
    }

    fn duplicate_inheritable_handle(
        source: HANDLE,
        label: &str,
    ) -> Result<OwnedKernelHandle, BridgeError> {
        if source.is_null() {
            return Err(envelope(
                "ASTRO_CBM_WORKER_CAPABILITY_HANDLE_DUPLICATE_FAILED",
                format!("the capability {label} source handle is null"),
                "Stop startup and inspect process-handle construction; do not launch a capability with ambiguous inheritance.",
            ));
        }
        // SAFETY: this pseudo-handle identifies the current process.
        let current = unsafe { GetCurrentProcess() };
        let mut duplicate = std::ptr::null_mut();
        // SAFETY: `source` is owned by this process, output storage is valid,
        // and only this duplicate is marked inheritable for HANDLE_LIST.
        if unsafe {
            DuplicateHandle(
                current,
                source,
                current,
                &mut duplicate,
                0,
                1,
                DUPLICATE_SAME_ACCESS,
            )
        } == 0
        {
            return Err(last_win32_failure(
                "ASTRO_CBM_WORKER_CAPABILITY_HANDLE_DUPLICATE_FAILED",
                format!("could not duplicate capability {label} as inheritable"),
                "Inspect Windows handle duplication; do not launch a capability with ambiguous inheritance.",
            ));
        }
        OwnedKernelHandle::new(duplicate).ok_or_else(|| {
            envelope(
                "ASTRO_CBM_WORKER_CAPABILITY_HANDLE_DUPLICATE_FAILED",
                format!("DuplicateHandle returned a null capability {label} handle"),
                "Stop startup and inspect Windows handle duplication; do not launch a capability with ambiguous inheritance.",
            )
        })
    }

    fn query_job_limits(
        handle: HANDLE,
    ) -> Result<JOBOBJECT_EXTENDED_LIMIT_INFORMATION, BridgeError> {
        let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
        let mut returned_len = 0_u32;
        // SAFETY: the Job handle is live and `limits` is writable for its exact
        // structure size; `returned_len` is a live output.
        if unsafe {
            QueryInformationJobObject(
                handle,
                JobObjectExtendedLimitInformation,
                std::ptr::from_mut(&mut limits).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
                &mut returned_len,
            )
        } == 0
        {
            return Err(last_win32_failure(
                "ASTRO_CBM_WORKER_CAPABILITY_JOB_QUERY_FAILED",
                "could not read back capability Job limits",
                "Stop startup and inspect Windows Job Object state; do not accept an unevaluable capability cohort.",
            ));
        }
        if returned_len != size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32 {
            return Err(envelope(
                "ASTRO_CBM_WORKER_CAPABILITY_JOB_QUERY_INVALID",
                format!(
                    "capability Job limit readback returned {returned_len} bytes, expected {}",
                    size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>()
                ),
                "Stop startup and inspect Windows Job Object state; do not accept a partial limit readback.",
            ));
        }
        Ok(limits)
    }

    #[derive(Debug)]
    struct CapabilityJobSnapshot {
        observation: CbmWorkerCapabilityJobSnapshot,
        process_ids: Vec<u32>,
    }

    #[derive(Clone, Copy)]
    enum JobEmptyExpectation {
        Normal {
            expected_pid: u32,
            expected_total_processes: u32,
            expected_total_terminated_processes: u32,
        },
        TerminatedCleanup,
    }

    #[derive(Debug)]
    struct JobEmptyReadback {
        consecutive_readbacks: u32,
        terminal_snapshot: CbmWorkerCapabilityJobSnapshot,
    }

    fn process_is_in_job(process: HANDLE, job: HANDLE) -> Result<bool, String> {
        let mut result = 0;
        // SAFETY: both exact handles are live and `result` is a writable BOOL.
        if unsafe { IsProcessInJob(process, job, &mut result) } == 0 {
            let os_code = unsafe { GetLastError() };
            return Err(format!("IsProcessInJob failed (GetLastError={os_code})"));
        }
        Ok(result != 0)
    }

    fn query_job_accounting(
        handle: HANDLE,
    ) -> Result<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, String> {
        let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        let mut accounting_bytes = 0_u32;
        // SAFETY: the Job handle is live and `accounting` is writable for its
        // exact structure size.
        if unsafe {
            QueryInformationJobObject(
                handle,
                JobObjectBasicAccountingInformation,
                std::ptr::from_mut(&mut accounting).cast(),
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
                &mut accounting_bytes,
            )
        } == 0
        {
            let os_code = unsafe { GetLastError() };
            return Err(format!(
                "QueryInformationJobObject(BasicAccounting) failed (GetLastError={os_code})"
            ));
        }
        if accounting_bytes != size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32 {
            return Err(format!(
                "capability Job accounting readback returned {accounting_bytes} bytes, expected {}",
                size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>()
            ));
        }
        Ok(accounting)
    }

    fn query_job_snapshot(handle: HANDLE) -> Result<CapabilityJobSnapshot, String> {
        // Bracket the variable-length PID-list query with independent Job
        // accounting reads. A process exit can race either call; only equal
        // membership-control counters on both sides form one stable snapshot.
        let accounting_before = query_job_accounting(handle)?;
        let mut processes = JOBOBJECT_BASIC_PROCESS_ID_LIST::default();
        let mut returned_len = 0_u32;
        // ACTIVE_PROCESS=1 bounds the live PID roster to the structure's one
        // inline slot. `NumberOfAssignedProcesses` may nevertheless exceed
        // `NumberOfProcessIdsInList` while a terminal process object is still
        // referenced, so that documented inequality is a transitional state,
        // never proof of emptiness.
        // SAFETY: the Job handle is live and the structure is writable for its
        // exact size.
        if unsafe {
            QueryInformationJobObject(
                handle,
                JobObjectBasicProcessIdList,
                std::ptr::from_mut(&mut processes).cast(),
                size_of::<JOBOBJECT_BASIC_PROCESS_ID_LIST>() as u32,
                &mut returned_len,
            )
        } == 0
        {
            let os_code = unsafe { GetLastError() };
            return Err(format!(
                "QueryInformationJobObject(ProcessIdList) failed (GetLastError={os_code})"
            ));
        }
        let assigned = processes.NumberOfAssignedProcesses;
        let listed = processes.NumberOfProcessIdsInList;
        if assigned > REQUIRED_ACTIVE_PROCESS_LIMIT
            || listed > assigned
            || listed > REQUIRED_ACTIVE_PROCESS_LIMIT
        {
            return Err(format!(
                "capability Job returned impossible PID counts: assigned={assigned}, listed={listed}, bytes={returned_len}"
            ));
        }
        let listed = usize::try_from(listed)
            .map_err(|_| "capability Job listed PID count does not fit usize".to_string())?;
        let required_bytes = PROCESS_LIST_OFFSET
            .checked_add(
                listed
                    .checked_mul(size_of::<usize>())
                    .ok_or_else(|| "capability Job PID-list byte count overflowed".to_string())?,
            )
            .ok_or_else(|| "capability Job PID-list size overflowed".to_string())?;
        if PROCESS_LIST_OFFSET >= size_of::<JOBOBJECT_BASIC_PROCESS_ID_LIST>()
            || required_bytes > size_of::<JOBOBJECT_BASIC_PROCESS_ID_LIST>()
            || (returned_len as usize) < required_bytes
            || (returned_len as usize) > size_of::<JOBOBJECT_BASIC_PROCESS_ID_LIST>()
        {
            return Err("capability Job PID-list layout is invalid".to_string());
        }
        let mut process_ids = Vec::with_capacity(listed);
        if listed == 1 {
            let process_id = u32::try_from(processes.ProcessIdList[0]).map_err(|_| {
                format!(
                    "capability Job returned unrepresentable process id {}",
                    processes.ProcessIdList[0]
                )
            })?;
            if process_id == 0 {
                return Err("capability Job returned process id zero".to_string());
            }
            process_ids.push(process_id);
        }
        let accounting_after = query_job_accounting(handle)?;
        Ok(CapabilityJobSnapshot {
            observation: CbmWorkerCapabilityJobSnapshot {
                accounting_before_total_processes: accounting_before.TotalProcesses,
                accounting_before_active_processes: accounting_before.ActiveProcesses,
                accounting_before_total_terminated_processes: accounting_before
                    .TotalTerminatedProcesses,
                total_processes: accounting_after.TotalProcesses,
                active_processes: accounting_after.ActiveProcesses,
                total_terminated_processes: accounting_after.TotalTerminatedProcesses,
                assigned_processes: assigned,
                listed_processes: processes.NumberOfProcessIdsInList,
                listed_process_id: process_ids.first().copied(),
            },
            process_ids,
        })
    }

    fn job_snapshot_accounting_is_stable(snapshot: &CapabilityJobSnapshot) -> bool {
        let state = snapshot.observation;
        state.accounting_before_total_processes == state.total_processes
            && state.accounting_before_active_processes == state.active_processes
            && state.accounting_before_total_terminated_processes
                == state.total_terminated_processes
    }

    fn validate_pre_spawn_job_snapshot(snapshot: &CapabilityJobSnapshot) -> Result<(), String> {
        let state = snapshot.observation;
        if !job_snapshot_accounting_is_stable(snapshot)
            || state.total_processes != 0
            || state.active_processes != 0
            || state.total_terminated_processes != 0
            || state.assigned_processes != 0
            || state.listed_processes != 0
            || state.listed_process_id.is_some()
            || !snapshot.process_ids.is_empty()
        {
            return Err(format!(
                "fresh capability Job was not exactly empty before process creation: snapshot={snapshot:?}"
            ));
        }
        Ok(())
    }

    fn validate_suspended_job_snapshot(
        snapshot: &CapabilityJobSnapshot,
        expected_pid: u32,
    ) -> Result<(), String> {
        let state = snapshot.observation;
        if !job_snapshot_accounting_is_stable(snapshot)
            || state.total_processes != 1
            || state.active_processes != REQUIRED_ACTIVE_PROCESS_LIMIT
            || state.total_terminated_processes != 0
            || state.assigned_processes != REQUIRED_ACTIVE_PROCESS_LIMIT
            || state.listed_processes != REQUIRED_ACTIVE_PROCESS_LIMIT
            || state.listed_process_id != Some(expected_pid)
            || snapshot.process_ids.as_slice() != [expected_pid]
        {
            return Err(format!(
                "suspended capability Job did not contain exactly its one primary process: expected_pid={expected_pid}, snapshot={snapshot:?}"
            ));
        }
        Ok(())
    }

    fn validate_normal_job_snapshot(
        snapshot: &CapabilityJobSnapshot,
        expected_pid: u32,
        expected_total_processes: u32,
        expected_total_terminated_processes: u32,
    ) -> Result<(), String> {
        let state = snapshot.observation;
        if state.accounting_before_total_processes != expected_total_processes
            || state.total_processes != expected_total_processes
            || state.accounting_before_total_terminated_processes
                != expected_total_terminated_processes
            || state.total_terminated_processes != expected_total_terminated_processes
            || state.accounting_before_active_processes > REQUIRED_ACTIVE_PROCESS_LIMIT
            || state.active_processes > REQUIRED_ACTIVE_PROCESS_LIMIT
            || snapshot
                .process_ids
                .iter()
                .any(|process_id| *process_id != expected_pid)
        {
            return Err(format!(
                "capability Job state changed from its suspended lifetime baseline or listed a foreign process: expected_pid={expected_pid}, expected_total_processes={expected_total_processes}, expected_total_terminated_processes={expected_total_terminated_processes}, snapshot={snapshot:?}"
            ));
        }
        Ok(())
    }

    fn wait_for_job_empty_twice(
        handle: HANDLE,
        deadline: Instant,
        expectation: JobEmptyExpectation,
    ) -> Result<JobEmptyReadback, String> {
        let mut consecutive = 0_u32;
        loop {
            let snapshot = query_job_snapshot(handle)?;
            let state = snapshot.observation;
            if let JobEmptyExpectation::Normal {
                expected_pid,
                expected_total_processes,
                expected_total_terminated_processes,
            } = expectation
            {
                validate_normal_job_snapshot(
                    &snapshot,
                    expected_pid,
                    expected_total_processes,
                    expected_total_terminated_processes,
                )?;
            }
            let empty = job_snapshot_accounting_is_stable(&snapshot)
                && state.accounting_before_active_processes == 0
                && state.active_processes == 0
                && state.assigned_processes == 0
                && state.listed_processes == 0
                && state.listed_process_id.is_none()
                && snapshot.process_ids.is_empty();
            if empty {
                consecutive += 1;
                if consecutive == REQUIRED_EMPTY_READBACKS {
                    return Ok(JobEmptyReadback {
                        consecutive_readbacks: consecutive,
                        terminal_snapshot: state,
                    });
                }
            } else {
                consecutive = 0;
            }
            if Instant::now() >= deadline {
                return Err(format!(
                    "capability Job did not produce {REQUIRED_EMPTY_READBACKS} consecutive paired empty readbacks before its deadline; last_snapshot={snapshot:?}"
                ));
            }
            thread::yield_now();
        }
    }

    fn read_bounded_pipe(mut file: File) -> CapabilityPipeRead {
        let mut bytes = Vec::new();
        let mut overflow = false;
        let mut total_bytes = 0_u64;
        let mut buffer = [0_u8; 8 * 1024];
        loop {
            match file.read(&mut buffer) {
                Ok(0) => {
                    return Ok(PipeCapture {
                        bytes,
                        overflow,
                        total_bytes,
                    });
                }
                Ok(read) => {
                    total_bytes = total_bytes.checked_add(read as u64).ok_or_else(|| {
                        std::io::Error::other("capability pipe byte count overflowed u64")
                    })?;
                    let remaining = WORKER_CAPABILITY_OUTPUT_MAX_BYTES.saturating_sub(bytes.len());
                    let retained = remaining.min(read);
                    bytes.extend_from_slice(&buffer[..retained]);
                    overflow |= retained != read;
                }
                Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                Err(error) => return Err(error),
            }
        }
    }

    fn extended_application_wide(path: &Path) -> Result<Vec<u16>, BridgeError> {
        let wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
        if wide.is_empty() || wide.contains(&0) {
            return Err(envelope(
                "ASTRO_CBM_WORKER_CAPABILITY_COMMAND_LINE_INVALID",
                "the retained capability application path is empty or contains an embedded NUL",
                "Pass one exact ordinary absolute executable path and a valid generated challenge.",
            ));
        }
        let separator = |unit: u16| unit == b'\\' as u16 || unit == b'/' as u16;
        let has_namespace_prefix = wide.len() >= 4
            && separator(wide[0])
            && separator(wide[1])
            && (wide[2] == b'?' as u16 || wide[2] == b'.' as u16)
            && separator(wide[3]);
        let mut application = if has_namespace_prefix {
            wide
        } else if wide.len() >= 2 && separator(wide[0]) && separator(wide[1]) {
            // A normalized UNC path becomes the documented extended UNC form.
            let mut extended = r"\\?\UNC\".encode_utf16().collect::<Vec<_>>();
            extended.extend_from_slice(&wide[2..]);
            extended
        } else if wide.len() >= 3 && wide[1] == b':' as u16 && separator(wide[2]) {
            // A normalized drive path becomes the documented extended drive
            // form. The command-line argv[0] remains the caller's original
            // spelling; only lpApplicationName uses this exact launch path.
            let mut extended = r"\\?\".encode_utf16().collect::<Vec<_>>();
            extended.extend_from_slice(&wide);
            extended
        } else {
            return Err(envelope(
                "ASTRO_CBM_WORKER_CAPABILITY_APPLICATION_PATH_INVALID",
                format!(
                    "the retained capability application path {} is not an absolute drive, UNC, or Windows namespace path",
                    path.display()
                ),
                "Pass the exact retained absolute shipping artifact path; executable search and drive-relative paths are forbidden.",
            ));
        };
        // Win32 namespace paths require backslash separators. Replacing `/` is
        // identity-preserving because `/` cannot be a Windows filename unit.
        for unit in &mut application {
            if *unit == b'/' as u16 {
                *unit = b'\\' as u16;
            }
        }
        application.push(0);
        if application.len() > MAX_WINDOWS_COMMAND_LINE_UNITS {
            return Err(envelope(
                "ASTRO_CBM_WORKER_CAPABILITY_APPLICATION_PATH_INVALID",
                format!(
                    "the extended capability application path is {} UTF-16 units, exceeding the Windows limit of {MAX_WINDOWS_COMMAND_LINE_UNITS}",
                    application.len()
                ),
                "Use the exact retained shipping artifact whose normalized extended path fits the Windows process-creation boundary.",
            ));
        }
        Ok(application)
    }

    fn windows_command_line(
        executable: &OsStr,
        arguments: &[&OsStr],
    ) -> Result<Vec<u16>, BridgeError> {
        let mut command_line = Vec::new();
        append_quoted_argument(&mut command_line, executable)?;
        for argument in arguments {
            command_line.push(b' ' as u16);
            append_quoted_argument(&mut command_line, argument)?;
        }
        command_line.push(0);
        if command_line.len() > MAX_WINDOWS_COMMAND_LINE_UNITS {
            return Err(envelope(
                "ASTRO_CBM_WORKER_CAPABILITY_COMMAND_LINE_INVALID",
                format!(
                    "the capability command line is {} UTF-16 units, exceeding the Windows limit of {MAX_WINDOWS_COMMAND_LINE_UNITS}",
                    command_line.len()
                ),
                "Use the exact published worker path and generated bounded challenge; do not truncate process arguments.",
            ));
        }
        Ok(command_line)
    }

    fn append_quoted_argument(
        command_line: &mut Vec<u16>,
        argument: &OsStr,
    ) -> Result<(), BridgeError> {
        let wide = argument.encode_wide().collect::<Vec<_>>();
        if wide.contains(&0) {
            return Err(envelope(
                "ASTRO_CBM_WORKER_CAPABILITY_COMMAND_LINE_INVALID",
                "a capability process argument contains an embedded NUL",
                "Use the exact published worker path and generated bounded challenge; do not truncate process arguments.",
            ));
        }
        command_line.push(b'"' as u16);
        let mut backslashes = 0_usize;
        for unit in wide {
            if unit == b'\\' as u16 {
                backslashes = backslashes.checked_add(1).ok_or_else(|| {
                    envelope(
                        "ASTRO_CBM_WORKER_CAPABILITY_COMMAND_LINE_INVALID",
                        "a capability process argument backslash count overflowed",
                        "Use the exact published worker path and generated bounded challenge.",
                    )
                })?;
                continue;
            }
            if unit == b'"' as u16 {
                extend_backslashes(command_line, backslashes, true, true)?;
                command_line.push(unit);
            } else {
                extend_backslashes(command_line, backslashes, false, false)?;
                command_line.push(unit);
            }
            backslashes = 0;
        }
        extend_backslashes(command_line, backslashes, true, false)?;
        command_line.push(b'"' as u16);
        Ok(())
    }

    fn extend_backslashes(
        command_line: &mut Vec<u16>,
        count: usize,
        double: bool,
        escape_quote: bool,
    ) -> Result<(), BridgeError> {
        let mut count = if double {
            count.checked_mul(2).ok_or_else(|| {
                envelope(
                    "ASTRO_CBM_WORKER_CAPABILITY_COMMAND_LINE_INVALID",
                    "a capability process argument quote escape count overflowed",
                    "Use the exact published worker path and generated bounded challenge.",
                )
            })?
        } else {
            count
        };
        if escape_quote {
            count = count.checked_add(1).ok_or_else(|| {
                envelope(
                    "ASTRO_CBM_WORKER_CAPABILITY_COMMAND_LINE_INVALID",
                    "a capability process argument quote escape count overflowed",
                    "Use the exact published worker path and generated bounded challenge.",
                )
            })?;
        }
        command_line.extend(std::iter::repeat_n(b'\\' as u16, count));
        Ok(())
    }

    fn wait_millis(deadline: Instant) -> Option<u32> {
        let remaining = deadline.checked_duration_since(Instant::now())?;
        let whole_millis = remaining.as_millis();
        if whole_millis == 0 {
            return None;
        }
        u32::try_from(whole_millis).ok().filter(|value| *value > 0)
    }

    fn wait_process(handle: HANDLE, deadline: Instant) -> Result<bool, String> {
        let Some(wait_ms) = wait_millis(deadline) else {
            return Ok(false);
        };
        // SAFETY: the caller retains the live process handle through this wait.
        match unsafe { WaitForSingleObject(handle, wait_ms) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            WAIT_FAILED => {
                let os_code = unsafe { GetLastError() };
                Err(format!(
                    "WaitForSingleObject(process) failed (GetLastError={os_code})"
                ))
            }
            status => Err(format!(
                "WaitForSingleObject(process) returned unexpected status {status:#x}"
            )),
        }
    }

    fn process_is_signaled_now(handle: HANDLE) -> Result<bool, String> {
        // SAFETY: the caller retains the live exact process handle through this
        // zero-duration state observation.
        match unsafe { WaitForSingleObject(handle, 0) } {
            WAIT_OBJECT_0 => Ok(true),
            WAIT_TIMEOUT => Ok(false),
            WAIT_FAILED => {
                let os_code = unsafe { GetLastError() };
                Err(format!(
                    "WaitForSingleObject(process, 0) failed (GetLastError={os_code})"
                ))
            }
            status => Err(format!(
                "WaitForSingleObject(process, 0) returned unexpected status {status:#x}"
            )),
        }
    }

    fn elapsed_micros(started: Instant) -> Result<u64, BridgeError> {
        u64::try_from(started.elapsed().as_micros()).map_err(|_| {
            envelope(
                "ASTRO_CBM_WORKER_CAPABILITY_ELAPSED_OVERFLOW",
                "the capability process elapsed time does not fit in u64 microseconds",
                "Stop startup and inspect the monotonic clock; do not publish an incomplete capability observation.",
            )
        })
    }

    fn cleanup_summary(context: CapabilityFailureContext<'_>) -> String {
        let CapabilityFailureContext {
            job,
            process,
            thread,
            known_exit_code,
            pid,
            readers,
            timeout_ms,
            terminal_deadline,
        } = context;
        let started = Instant::now();
        let remaining_at_entry_micros = terminal_deadline
            .checked_duration_since(started)
            .map(|remaining| remaining.as_micros())
            .unwrap_or(0);
        // SAFETY: this private Job handle remains live for the complete bounded
        // cleanup phase and owns every process in the capability cohort.
        let termination =
            if unsafe { TerminateJobObject(job.raw(), CAPABILITY_TERMINATION_EXIT_CODE) } != 0 {
                "ok".to_string()
            } else {
                let os_code = unsafe { GetLastError() };
                format!("failed(GetLastError={os_code})")
            };
        let (thread_handle_close, retained_thread) = match thread {
            Some(thread) => match thread.close() {
                Ok(()) => ("ok".to_string(), None),
                Err((thread, os_code)) => (
                    format!("failed(GetLastError={os_code}, retained_reference=true)"),
                    Some(thread),
                ),
            },
            None => ("not_owned".to_string(), None),
        };
        let process_terminal = match process.as_ref() {
            Some(process) => match wait_process(process.raw(), terminal_deadline) {
                Ok(true) => {
                    let mut exit_code = 0_u32;
                    // SAFETY: the bounded wait observed this exact retained
                    // process handle signaled and `exit_code` is writable.
                    if unsafe { GetExitCodeProcess(process.raw(), &mut exit_code) } != 0 {
                        format!("signaled(exit_code={exit_code})")
                    } else {
                        let os_code = unsafe { GetLastError() };
                        format!("signaled(exit_query_failed(GetLastError={os_code}))")
                    }
                }
                Ok(false) => "deadline".to_string(),
                Err(error) => format!("wait_failed({error})"),
            },
            None => known_exit_code.map_or_else(
                || "unavailable".to_string(),
                |exit_code| format!("captured_before_cleanup(exit_code={exit_code})"),
            ),
        };
        // BasicAccounting.ActiveProcesses is decremented only after the
        // terminal process and every retained process-object reference are
        // released. Drop the exact parent handle before asking the Job to prove
        // that its terminated cohort is physically empty.
        let (process_handle_close, retained_process) = match process {
            Some(process) => match process.close() {
                Ok(()) => ("ok".to_string(), None),
                Err((process, os_code)) => (
                    format!("failed(GetLastError={os_code}, retained_reference=true)"),
                    Some(process),
                ),
            },
            None => ("not_owned".to_string(), None),
        };
        let job_empty = if retained_process.is_some() || retained_thread.is_some() {
            format!(
                "unevaluable(handle_close_failed, retained_process_reference={}, retained_thread_reference={})",
                retained_process.is_some(),
                retained_thread.is_some()
            )
        } else {
            format!(
                "{:?}",
                wait_for_job_empty_twice(
                    job.raw(),
                    terminal_deadline,
                    JobEmptyExpectation::TerminatedCleanup,
                )
            )
        };
        let (stdout, stderr) = readers.finish(terminal_deadline);
        let stdout = pipe_result_summary(&stdout);
        let stderr = pipe_result_summary(&stderr);
        let elapsed = started.elapsed().as_micros();
        format!(
            "pid={pid}, total_timeout_ms={timeout_ms}, remaining_at_entry_micros={remaining_at_entry_micros}, cleanup_elapsed_micros={elapsed}, job_termination={termination}, process_terminal={process_terminal}, primary_thread_handle_close={thread_handle_close}, process_handle_close={process_handle_close}, job_empty={job_empty}, stdout={stdout}, stderr={stderr}"
        )
    }

    struct CapabilityFailureContext<'a> {
        job: &'a CapabilityJob,
        process: Option<OwnedKernelHandle>,
        thread: Option<OwnedKernelHandle>,
        known_exit_code: Option<u32>,
        pid: u32,
        readers: &'a mut CapabilityReaders,
        timeout_ms: u32,
        terminal_deadline: Instant,
    }

    fn failure_after_spawn(
        code: &'static str,
        message: String,
        remediation: &'static str,
        context: CapabilityFailureContext<'_>,
    ) -> BridgeError {
        let cleanup = cleanup_summary(context);
        envelope(code, format!("{message}; cleanup=({cleanup})"), remediation)
    }

    fn last_win32_failure(
        code: &'static str,
        message: impl Into<String>,
        remediation: &'static str,
    ) -> BridgeError {
        // SAFETY: callers invoke this immediately after the failed Win32 call.
        let os_code = unsafe { GetLastError() };
        win32_failure(code, message, os_code, remediation)
    }

    fn win32_failure(
        code: &'static str,
        message: impl Into<String>,
        os_code: u32,
        remediation: &'static str,
    ) -> BridgeError {
        envelope(
            code,
            format!("{} (GetLastError={os_code})", message.into()),
            remediation,
        )
    }

    pub(super) fn run(
        application_path: &Path,
        argv0_path: &Path,
        challenge: &str,
    ) -> Result<BoundedCapabilityProcess, BridgeError> {
        let timeout_ms = astrolabe_domain::knobs::worker_capability_timeout_ms();
        if timeout_ms < 2 || timeout_ms == u32::MAX {
            return Err(envelope(
                "ASTRO_CBM_WORKER_CAPABILITY_TIMEOUT_INVALID",
                format!(
                    "worker_capability_timeout_ms is {timeout_ms}; the capability deadline must be finite and leave positive execution and cleanup intervals"
                ),
                "Repair the registered worker capability timeout before startup; zero and INFINITE are not valid execution budgets.",
            ));
        }
        let started = Instant::now();
        // The registered knob is one end-to-end wall-time bound. Reserve one
        // quarter for TerminateJobObject + process/Job/pipe readback so a hung
        // execution cannot silently expand the bound to 2x. N is invariant at
        // one primary process because ACTIVE_PROCESS=1 is read back above.
        let cleanup_reserve_ms = timeout_ms.div_ceil(CLEANUP_RESERVE_DIVISOR);
        let execution_budget_ms = timeout_ms.checked_sub(cleanup_reserve_ms).ok_or_else(|| {
            envelope(
                "ASTRO_CBM_WORKER_CAPABILITY_TIMEOUT_INVALID",
                format!(
                    "worker_capability_timeout_ms={timeout_ms} cannot reserve cleanup_ms={cleanup_reserve_ms}"
                ),
                "Repair the registered end-to-end capability timeout before startup.",
            )
        })?;
        let terminal_deadline = started
            .checked_add(Duration::from_millis(u64::from(timeout_ms)))
            .ok_or_else(|| {
                envelope(
                    "ASTRO_CBM_WORKER_CAPABILITY_DEADLINE_OVERFLOW",
                    format!("the {timeout_ms} ms capability deadline exceeds the monotonic clock"),
                    "Repair the registered worker capability timeout before startup; do not execute without a finite deadline.",
                )
            })?;
        let execution_deadline = started
            .checked_add(Duration::from_millis(u64::from(execution_budget_ms)))
            .ok_or_else(|| {
                envelope(
                    "ASTRO_CBM_WORKER_CAPABILITY_DEADLINE_OVERFLOW",
                    format!(
                        "the {execution_budget_ms} ms capability execution deadline exceeds the monotonic clock"
                    ),
                    "Repair the registered worker capability timeout before startup; do not execute without a finite deadline.",
                )
            })?;
        let job = CapabilityJob::create()?;
        let job_pre_spawn = query_job_snapshot(job.raw()).map_err(|error| {
            envelope(
                "ASTRO_CBM_WORKER_CAPABILITY_JOB_QUERY_FAILED",
                format!("fresh capability Job pre-spawn readback failed: {error}"),
                "Stop startup and inspect the exact private Job; do not create a capability process from an unevaluable baseline.",
            )
        })?;
        validate_pre_spawn_job_snapshot(&job_pre_spawn).map_err(|error| {
            envelope(
                "ASTRO_CBM_WORKER_CAPABILITY_JOB_PRESPAWN_NOT_EMPTY",
                error,
                "Stop startup and inspect private Job creation; never reuse or execute from a Job whose exact initial accounting is nonempty.",
            )
        })?;
        let job_pre_spawn_snapshot = job_pre_spawn.observation;
        let stdout_pipe = create_pipe("stdout")?;
        let stderr_pipe = create_pipe("stderr")?;
        let stdin = File::open("NUL").map_err(|error| {
            envelope(
                "ASTRO_CBM_WORKER_CAPABILITY_STDIN_OPEN_FAILED",
                format!("could not open Windows NUL for capability stdin: {error}"),
                "Inspect the Windows NUL device; do not launch a capability with inherited or interactive stdin.",
            )
        })?;
        let inherited_stdin = duplicate_inheritable_handle(stdin.as_raw_handle().cast(), "stdin")?;
        let mut readers = CapabilityReaders {
            stdout: Some(CapabilityReader::spawn("stdout", stdout_pipe.reader)?),
            stderr: Some(CapabilityReader::spawn("stderr", stderr_pipe.reader)?),
        };
        let inherited_handles = [
            inherited_stdin.raw(),
            stdout_pipe.child_writer.raw(),
            stderr_pipe.child_writer.raw(),
        ];
        let job_handles = [job.raw()];
        let mut attributes = ProcThreadAttributeList::new()?;
        attributes.update_handles(
            PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
            &job_handles,
            "atomic Job list",
        )?;
        attributes.update_handles(
            PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
            &inherited_handles,
            "inherited standard-handle list",
        )?;
        let application = extended_application_wide(application_path)?;
        let mut command_line = windows_command_line(
            argv0_path.as_os_str(),
            [
                OsStr::new(ASTRO_INDEX_WORKER_CAPABILITY_ARG),
                OsStr::new(challenge),
            ]
            .as_slice(),
        )?;
        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.StartupInfo.hStdInput = inherited_stdin.raw();
        startup.StartupInfo.hStdOutput = stdout_pipe.child_writer.raw();
        startup.StartupInfo.hStdError = stderr_pipe.child_writer.raw();
        startup.lpAttributeList = attributes.raw();
        let mut process_info = PROCESS_INFORMATION::default();
        if Instant::now() >= execution_deadline {
            drop(attributes);
            drop(inherited_stdin);
            drop(stdout_pipe.child_writer);
            drop(stderr_pipe.child_writer);
            drop(stdin);
            let (stdout, stderr) = readers.finish(terminal_deadline);
            let stdout = pipe_result_summary(&stdout);
            let stderr = pipe_result_summary(&stderr);
            return Err(envelope(
                "ASTRO_CBM_WORKER_CAPABILITY_PRESPAWN_TIMEOUT",
                format!(
                    "capability setup exhausted its {execution_budget_ms} ms execution interval before CreateProcessW; total_timeout_ms={timeout_ms}, cleanup_reserve_ms={cleanup_reserve_ms}, stdout={stdout}, stderr={stderr}"
                ),
                "Inspect capability setup latency; do not launch a process after its reserved execution interval has expired.",
            ));
        }
        // SAFETY: all pointer-backed application, command-line, startup, Job,
        // and handle-list storage remains live for the call. The explicit
        // application path disables executable search, and HANDLE_LIST limits
        // inheritance to the three standard handles. DETACHED_PROCESS avoids a
        // console-host process in this noninteractive protocol; the explicit
        // pipe handles remain its only standard streams. CREATE_SUSPENDED lets
        // the parent prove the exact Job generation before application code.
        let created = unsafe {
            CreateProcessW(
                application.as_ptr(),
                command_line.as_mut_ptr(),
                std::ptr::null(),
                std::ptr::null(),
                1,
                DETACHED_PROCESS | CREATE_SUSPENDED | EXTENDED_STARTUPINFO_PRESENT,
                std::ptr::null(),
                std::ptr::null(),
                std::ptr::from_ref(&startup).cast::<STARTUPINFOW>(),
                &mut process_info,
            )
        };
        // GetLastError is process-thread state and must be captured before any
        // handle close can overwrite the CreateProcessW failure diagnostic.
        let create_error = (created == 0).then(|| unsafe { GetLastError() });
        // The parent must release every inheritable pipe writer immediately so
        // EOF is produced only by the Job-owned process generation.
        drop(attributes);
        drop(inherited_stdin);
        drop(stdout_pipe.child_writer);
        drop(stderr_pipe.child_writer);
        drop(stdin);
        if let Some(os_code) = create_error {
            let (stdout, stderr) = readers.finish(terminal_deadline);
            let stdout = pipe_result_summary(&stdout);
            let stderr = pipe_result_summary(&stderr);
            return Err(win32_failure(
                "ASTRO_CBM_WORKER_CAPABILITY_SPAWN_FAILED",
                format!(
                    "the retained worker executable {} could not be created atomically in its capability Job (stdout={stdout}, stderr={stderr})",
                    application_path.display()
                ),
                os_code,
                "Inspect the exact executable and Windows atomic process-creation error; do not enable indexing.",
            ));
        }
        let process = OwnedKernelHandle::new(process_info.hProcess);
        let thread = OwnedKernelHandle::new(process_info.hThread);
        let child_pid = process_info.dwProcessId;
        let primary_thread_id = process_info.dwThreadId;
        let (process, thread) = match (process, thread) {
            (Some(process), Some(thread)) if child_pid != 0 && primary_thread_id != 0 => {
                (process, thread)
            }
            (process, thread) => {
                return Err(failure_after_spawn(
                    "ASTRO_CBM_WORKER_CAPABILITY_PROCESS_IDENTITY_INVALID",
                    format!(
                        "CreateProcessW returned child_pid={child_pid}, primary_thread_id={primary_thread_id}, process_handle={}, thread_handle={} for {}",
                        process.is_some(),
                        thread.is_some(),
                        application_path.display()
                    ),
                    "Stop startup and inspect the exact CreateProcessW result; do not accept a capability without retained process and primary-thread identities.",
                    CapabilityFailureContext {
                        job: &job,
                        process,
                        thread,
                        known_exit_code: None,
                        pid: child_pid,
                        readers: &mut readers,
                        timeout_ms,
                        terminal_deadline,
                    },
                ));
            }
        };
        let initial_membership = match process_is_in_job(process.raw(), job.raw()) {
            Ok(assigned) => assigned,
            Err(error) => {
                return Err(failure_after_spawn(
                    "ASTRO_CBM_WORKER_CAPABILITY_JOB_QUERY_FAILED",
                    format!(
                        "capability child {child_pid} exact-handle Job membership readback failed: {error}"
                    ),
                    "Stop startup and inspect the exact Job and process; do not accept an unevaluable atomic assignment.",
                    CapabilityFailureContext {
                        job: &job,
                        process: Some(process),
                        thread: Some(thread),
                        known_exit_code: None,
                        pid: child_pid,
                        readers: &mut readers,
                        timeout_ms,
                        terminal_deadline,
                    },
                ));
            }
        };
        if !initial_membership {
            return Err(failure_after_spawn(
                "ASTRO_CBM_WORKER_CAPABILITY_JOB_MEMBERSHIP_MISMATCH",
                format!(
                    "suspended capability child {child_pid} was not assigned to its exact private Job before its primary thread could run"
                ),
                "Stop startup and inspect the atomic JOB_LIST assignment; never resume a capability outside its exact private Job.",
                CapabilityFailureContext {
                    job: &job,
                    process: Some(process),
                    thread: Some(thread),
                    known_exit_code: None,
                    pid: child_pid,
                    readers: &mut readers,
                    timeout_ms,
                    terminal_deadline,
                },
            ));
        }
        match process_is_signaled_now(process.raw()) {
            Ok(false) => {}
            Ok(true) => {
                return Err(failure_after_spawn(
                    "ASTRO_CBM_WORKER_CAPABILITY_SUSPENDED_PROCESS_TERMINAL",
                    format!(
                        "capability child {child_pid} was already terminal before its suspended primary thread was resumed"
                    ),
                    "Stop startup and inspect image initialization; never accept a capability that terminated before its pre-execution Job state was proven.",
                    CapabilityFailureContext {
                        job: &job,
                        process: Some(process),
                        thread: Some(thread),
                        known_exit_code: None,
                        pid: child_pid,
                        readers: &mut readers,
                        timeout_ms,
                        terminal_deadline,
                    },
                ));
            }
            Err(error) => {
                return Err(failure_after_spawn(
                    "ASTRO_CBM_WORKER_CAPABILITY_JOB_QUERY_FAILED",
                    format!(
                        "suspended capability child {child_pid} exact-handle state readback failed: {error}"
                    ),
                    "Stop startup and inspect the exact process handle; do not resume an unevaluable capability.",
                    CapabilityFailureContext {
                        job: &job,
                        process: Some(process),
                        thread: Some(thread),
                        known_exit_code: None,
                        pid: child_pid,
                        readers: &mut readers,
                        timeout_ms,
                        terminal_deadline,
                    },
                ));
            }
        }
        let job_suspended = match query_job_snapshot(job.raw()) {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return Err(failure_after_spawn(
                    "ASTRO_CBM_WORKER_CAPABILITY_JOB_QUERY_FAILED",
                    format!(
                        "suspended capability child {child_pid} Job readback failed before resume: {error}"
                    ),
                    "Stop startup and inspect the exact Job accounting; do not resume an unevaluable capability generation.",
                    CapabilityFailureContext {
                        job: &job,
                        process: Some(process),
                        thread: Some(thread),
                        known_exit_code: None,
                        pid: child_pid,
                        readers: &mut readers,
                        timeout_ms,
                        terminal_deadline,
                    },
                ));
            }
        };
        if let Err(error) = validate_suspended_job_snapshot(&job_suspended, child_pid) {
            return Err(failure_after_spawn(
                "ASTRO_CBM_WORKER_CAPABILITY_JOB_MEMBERSHIP_MISMATCH",
                error,
                "Stop startup and inspect DETACHED_PROCESS plus the atomic JOB_LIST assignment; never resume anything except the exact one-process suspended cohort.",
                CapabilityFailureContext {
                    job: &job,
                    process: Some(process),
                    thread: Some(thread),
                    known_exit_code: None,
                    pid: child_pid,
                    readers: &mut readers,
                    timeout_ms,
                    terminal_deadline,
                },
            ));
        }
        let job_suspended_snapshot = job_suspended.observation;
        if Instant::now() >= execution_deadline {
            return Err(failure_after_spawn(
                "ASTRO_CBM_WORKER_CAPABILITY_PRERESUME_TIMEOUT",
                format!(
                    "capability setup exhausted its {execution_budget_ms} ms execution interval after proving suspended child {child_pid} and before ResumeThread; total_timeout_ms={timeout_ms}, cleanup_reserve_ms={cleanup_reserve_ms}, suspended_job={job_suspended_snapshot:?}"
                ),
                "Inspect suspended capability setup latency; never resume a process after its reserved execution interval has expired.",
                CapabilityFailureContext {
                    job: &job,
                    process: Some(process),
                    thread: Some(thread),
                    known_exit_code: None,
                    pid: child_pid,
                    readers: &mut readers,
                    timeout_ms,
                    terminal_deadline,
                },
            ));
        }
        // SAFETY: the retained primary-thread handle belongs to the exact
        // CREATE_SUSPENDED process. A return of one proves this call released
        // its sole creation-time suspend count.
        let resume_previous_suspend_count = unsafe { ResumeThread(thread.raw()) };
        if resume_previous_suspend_count == u32::MAX {
            let os_code = unsafe { GetLastError() };
            return Err(failure_after_spawn(
                "ASTRO_CBM_WORKER_CAPABILITY_RESUME_FAILED",
                format!(
                    "resuming capability child {child_pid} primary thread {primary_thread_id} failed (GetLastError={os_code})"
                ),
                "Stop startup and inspect the exact suspended thread; do not substitute another process or retry through executable search.",
                CapabilityFailureContext {
                    job: &job,
                    process: Some(process),
                    thread: Some(thread),
                    known_exit_code: None,
                    pid: child_pid,
                    readers: &mut readers,
                    timeout_ms,
                    terminal_deadline,
                },
            ));
        }
        if resume_previous_suspend_count != 1 {
            return Err(failure_after_spawn(
                "ASTRO_CBM_WORKER_CAPABILITY_SUSPEND_COUNT_INVALID",
                format!(
                    "resuming capability child {child_pid} primary thread {primary_thread_id} returned previous_suspend_count={resume_previous_suspend_count}, expected exactly 1"
                ),
                "Stop startup and inspect process creation; never accept a capability whose primary-thread execution boundary was not exact.",
                CapabilityFailureContext {
                    job: &job,
                    process: Some(process),
                    thread: Some(thread),
                    known_exit_code: None,
                    pid: child_pid,
                    readers: &mut readers,
                    timeout_ms,
                    terminal_deadline,
                },
            ));
        }
        if let Err((thread, os_code)) = thread.close() {
            return Err(failure_after_spawn(
                "ASTRO_CBM_WORKER_CAPABILITY_THREAD_HANDLE_CLOSE_FAILED",
                format!(
                    "capability child {child_pid} resumed from exactly one suspend count, but closing primary thread {primary_thread_id} failed (GetLastError={os_code})"
                ),
                "Stop startup and inspect the exact primary-thread handle lifecycle; do not accept output while the parent reference remains live.",
                CapabilityFailureContext {
                    job: &job,
                    process: Some(process),
                    thread: Some(thread),
                    known_exit_code: None,
                    pid: child_pid,
                    readers: &mut readers,
                    timeout_ms,
                    terminal_deadline,
                },
            ));
        }
        match wait_process(process.raw(), execution_deadline) {
            Ok(true) => {}
            Ok(false) => {
                return Err(failure_after_spawn(
                    "ASTRO_CBM_WORKER_CAPABILITY_TIMEOUT",
                    format!(
                        "capability child {child_pid} did not finish within its {execution_budget_ms} ms execution interval; total_timeout_ms={timeout_ms}, cleanup_reserve_ms={cleanup_reserve_ms}"
                    ),
                    "Inspect the exact non-mutating child; do not consume the reserved terminal-cleanup interval or enable indexing until the capability path terminates normally.",
                    CapabilityFailureContext {
                        job: &job,
                        process: Some(process),
                        thread: None,
                        known_exit_code: None,
                        pid: child_pid,
                        readers: &mut readers,
                        timeout_ms,
                        terminal_deadline,
                    },
                ));
            }
            Err(error) => {
                return Err(failure_after_spawn(
                    "ASTRO_CBM_WORKER_CAPABILITY_WAIT_FAILED",
                    format!("waiting for capability child {child_pid} failed: {error}"),
                    "Inspect the exact Windows wait and process identity; do not enable indexing after an unevaluable capability process.",
                    CapabilityFailureContext {
                        job: &job,
                        process: Some(process),
                        thread: None,
                        known_exit_code: None,
                        pid: child_pid,
                        readers: &mut readers,
                        timeout_ms,
                        terminal_deadline,
                    },
                ));
            }
        }
        let mut exit_code = 0_u32;
        // SAFETY: the process has signaled and the retained handle remains live.
        if unsafe { GetExitCodeProcess(process.raw(), &mut exit_code) } == 0 {
            let error = unsafe { GetLastError() };
            return Err(failure_after_spawn(
                "ASTRO_CBM_WORKER_CAPABILITY_EXIT_READBACK_FAILED",
                format!(
                    "capability child {child_pid} signaled but GetExitCodeProcess failed (GetLastError={error})"
                ),
                "Stop startup and inspect the exact process handle; do not accept a capability with an unreadable terminal state.",
                CapabilityFailureContext {
                    job: &job,
                    process: Some(process),
                    thread: None,
                    known_exit_code: None,
                    pid: child_pid,
                    readers: &mut readers,
                    timeout_ms,
                    terminal_deadline,
                },
            ));
        }
        // The exact child has signaled and its exit code is retained. Release
        // the parent process-object reference before Job accounting/PID-list
        // emptiness readback; Windows does not decrement ActiveProcesses until
        // every such reference is gone.
        if let Err((process, os_code)) = process.close() {
            return Err(failure_after_spawn(
                "ASTRO_CBM_WORKER_CAPABILITY_PROCESS_HANDLE_CLOSE_FAILED",
                format!(
                    "capability child {child_pid} signaled with exit_code={exit_code}, but closing its retained process handle failed (GetLastError={os_code})"
                ),
                "Stop startup and inspect the exact Windows process-handle lifecycle; do not accept output when the parent reference could not be released.",
                CapabilityFailureContext {
                    job: &job,
                    process: Some(process),
                    thread: None,
                    known_exit_code: Some(exit_code),
                    pid: child_pid,
                    readers: &mut readers,
                    timeout_ms,
                    terminal_deadline,
                },
            ));
        }
        let job_empty = match wait_for_job_empty_twice(
            job.raw(),
            execution_deadline,
            JobEmptyExpectation::Normal {
                expected_pid: child_pid,
                expected_total_processes: job_suspended_snapshot.total_processes,
                expected_total_terminated_processes: job_suspended_snapshot
                    .total_terminated_processes,
            },
        ) {
            Ok(readbacks) => readbacks,
            Err(error) => {
                return Err(failure_after_spawn(
                    "ASTRO_CBM_WORKER_CAPABILITY_JOB_NOT_EMPTY",
                    format!(
                        "capability child {child_pid} exited but its Job did not become provably empty: {error}"
                    ),
                    "Stop startup and inspect the exact capability Job cohort; do not accept output while any member state remains.",
                    CapabilityFailureContext {
                        job: &job,
                        process: None,
                        thread: None,
                        known_exit_code: Some(exit_code),
                        pid: child_pid,
                        readers: &mut readers,
                        timeout_ms,
                        terminal_deadline,
                    },
                ));
            }
        };
        let job_empty_readbacks = job_empty.consecutive_readbacks;
        let job_terminal_snapshot = job_empty.terminal_snapshot;
        let (stdout, stderr) = readers.finish(execution_deadline);
        let stdout = stdout.map_err(|error| {
            envelope(
                "ASTRO_CBM_WORKER_CAPABILITY_STDOUT_READ_FAILED",
                format!(
                    "capability child {child_pid} stdout did not reach bounded EOF: {error}; timeout_ms={timeout_ms}, job_empty_readbacks={job_empty_readbacks}"
                ),
                "Stop startup and inspect the exact pipe ownership; do not accept a capability without complete bounded stdout.",
            )
        })?;
        let stderr = stderr.map_err(|error| {
            envelope(
                "ASTRO_CBM_WORKER_CAPABILITY_STDERR_READ_FAILED",
                format!(
                    "capability child {child_pid} stderr did not reach bounded EOF: {error}; timeout_ms={timeout_ms}, job_empty_readbacks={job_empty_readbacks}"
                ),
                "Stop startup and inspect the exact pipe ownership; do not accept a capability without complete bounded stderr.",
            )
        })?;
        if stdout.overflow || stderr.overflow {
            return Err(envelope(
                "ASTRO_CBM_WORKER_CAPABILITY_OUTPUT_OVERSIZED",
                format!(
                    "capability child {child_pid} exceeded the structural {}-byte cap (stdout_bytes={}, stdout_overflow={}, stderr_bytes={}, stderr_overflow={}, timeout_ms={timeout_ms}, job_empty_readbacks={job_empty_readbacks})",
                    WORKER_CAPABILITY_OUTPUT_MAX_BYTES,
                    stdout.total_bytes,
                    stdout.overflow,
                    stderr.total_bytes,
                    stderr.overflow
                ),
                "Repair the fixed capability output to emit one bounded receipt and bounded diagnostics; do not enable indexing.",
            ));
        }
        let elapsed_micros = elapsed_micros(started)?;
        let execution_budget_micros = u64::from(execution_budget_ms) * 1_000;
        if elapsed_micros > execution_budget_micros {
            return Err(envelope(
                "ASTRO_CBM_WORKER_CAPABILITY_TIMEOUT",
                format!(
                    "capability child {child_pid} completed its process, Job, and pipe readbacks after its execution interval: elapsed_micros={elapsed_micros}, execution_budget_micros={execution_budget_micros}, total_timeout_ms={timeout_ms}, cleanup_reserve_ms={cleanup_reserve_ms}, job_empty_readbacks={job_empty_readbacks}, stdout_bytes={}, stderr_bytes={}",
                    stdout.total_bytes, stderr.total_bytes
                ),
                "Inspect the exact capability path; do not accept a receipt that consumed the terminal-cleanup reserve.",
            ));
        }
        Ok(BoundedCapabilityProcess {
            output: Output {
                status: std::process::ExitStatus::from_raw(exit_code),
                stdout: stdout.bytes,
                stderr: stderr.bytes,
            },
            observation: CbmWorkerCapabilityObservation {
                child_pid,
                primary_thread_id,
                resume_previous_suspend_count,
                timeout_ms,
                elapsed_micros,
                stdout_bytes: stdout.total_bytes,
                stderr_bytes: stderr.total_bytes,
                job_empty_readbacks,
                job_pre_spawn_snapshot,
                job_suspended_snapshot,
                job_terminal_snapshot,
            },
        })
    }
}

#[cfg(windows)]
fn run_bounded_capability_process(
    application_path: &Path,
    argv0_path: &Path,
    challenge: &str,
) -> Result<BoundedCapabilityProcess, BridgeError> {
    capability_process::run(application_path, argv0_path, challenge)
}

#[cfg(not(windows))]
fn run_bounded_capability_process(
    _application_path: &Path,
    _argv0_path: &Path,
    _challenge: &str,
) -> Result<BoundedCapabilityProcess, BridgeError> {
    Err(envelope(
        "ASTRO_CBM_WORKER_BINARY_PLATFORM_DEFERRED",
        "external worker capability processes are unavailable outside the native Windows target",
        "Run the native Windows shipping target; cross-platform worker binding is deferred.",
    ))
}

#[cfg(windows)]
fn open_external_worker_lease(path: &Path) -> Result<ExternalWorkerLease, BridgeError> {
    use std::os::windows::fs::MetadataExt;
    use std::os::windows::fs::OpenOptionsExt;
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
    };

    let metadata = fs::symlink_metadata(path).map_err(|error| {
        let code = if error.kind() == std::io::ErrorKind::NotFound {
            "ASTRO_CBM_WORKER_BINARY_MISSING"
        } else {
            "ASTRO_CBM_WORKER_BINARY_METADATA_FAILED"
        };
        envelope(
            code,
            format!("the external worker path {} could not be inspected: {error}", path.display()),
            "Pass one existing ordinary non-reparse Astrolabe executable and inspect the filesystem error.",
        )
    })?;
    if !metadata.is_file() {
        return Err(envelope(
            "ASTRO_CBM_WORKER_BINARY_NOT_ORDINARY",
            format!(
                "the external worker path {} is not an ordinary file",
                path.display()
            ),
            "Pass the exact shipping Astrolabe executable, not a directory or other filesystem object.",
        ));
    }
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(envelope(
            "ASTRO_CBM_WORKER_BINARY_REPARSE",
            format!(
                "the external worker path {} is a reparse point",
                path.display()
            ),
            "Pass the direct ordinary shipping Astrolabe executable path.",
        ));
    }

    let file = OpenOptions::new()
        .read(true)
        // Deny write/delete sharing from capability launch through the native
        // retained-handle bind. The candidate bytes cannot be replaced in the
        // preflight-to-publication window.
        .share_mode(FILE_SHARE_READ)
        // Open the namespace object itself so a reparse point installed after
        // the lstat-style precheck cannot redirect this retained authority.
        .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
        .open(path)
        .map_err(|error| {
            envelope(
                "ASTRO_CBM_WORKER_BINARY_OPEN_FAILED",
                format!(
                    "the external worker executable {} could not be retained for capability verification: {error}",
                    path.display()
                ),
                "Pass one existing ordinary non-reparse Astrolabe executable whose bytes are readable.",
            )
        })?;
    let identity = windows_file_identity_from_open_file(path, &file).map_err(|error| {
        let code = match error.step {
            "file_kind" => "ASTRO_CBM_WORKER_BINARY_NOT_ORDINARY",
            "file_reparse" => "ASTRO_CBM_WORKER_BINARY_REPARSE",
            "file_empty" => "ASTRO_CBM_WORKER_BINARY_EMPTY",
            _ => "ASTRO_CBM_WORKER_BINARY_IDENTITY_FAILED",
        };
        envelope(
            code,
            format!(
                "the external worker executable {} failed identity validation at {}: {}",
                path.display(),
                error.step,
                error.message
            ),
            "Pass one readable, non-empty ordinary Astrolabe executable and inspect the reported filesystem operation.",
        )
    })?;
    Ok(ExternalWorkerLease { file, identity })
}

#[cfg(not(windows))]
fn open_external_worker_lease(path: &Path) -> Result<ExternalWorkerLease, BridgeError> {
    let file = File::open(path).map_err(|error| {
        envelope(
            "ASTRO_CBM_WORKER_BINARY_OPEN_FAILED",
            format!(
                "the external worker executable {} could not be opened: {error}",
                path.display()
            ),
            "Run the native Windows shipping target; cross-platform worker binding is deferred.",
        )
    })?;
    drop(file);
    Err(envelope(
        "ASTRO_CBM_WORKER_BINARY_PLATFORM_DEFERRED",
        format!(
            "external worker identity for {} is unavailable outside the native Windows target",
            path.display()
        ),
        "Run the native Windows shipping target; cross-platform worker binding is deferred.",
    ))
}

fn retained_file_sha256(file: &mut File) -> Result<String, BridgeError> {
    file.seek(SeekFrom::Start(0)).map_err(|error| {
        envelope(
            "ASTRO_CBM_WORKER_ARTIFACT_HASH_SEEK_FAILED",
            format!("the retained worker executable could not seek to its first byte: {error}"),
            "Inspect the exact executable handle and filesystem error; do not bind an artifact whose bytes cannot be read deterministically.",
        )
    })?;
    let mut digest = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        match file.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => digest.update(&buffer[..read]),
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(envelope(
                    "ASTRO_CBM_WORKER_ARTIFACT_HASH_READ_FAILED",
                    format!("the retained worker executable could not be hashed: {error}"),
                    "Inspect the exact executable handle and filesystem error; do not bind an artifact whose complete bytes cannot be read.",
                ));
            }
        }
    }
    file.seek(SeekFrom::Start(0)).map_err(|error| {
        envelope(
            "ASTRO_CBM_WORKER_ARTIFACT_HASH_REWIND_FAILED",
            format!("the retained worker executable could not be rewound after hashing: {error}"),
            "Inspect the exact executable handle and filesystem error; do not publish a binding after incomplete artifact readback.",
        )
    })?;
    Ok(format!("{:x}", digest.finalize()))
}

fn verify_external_worker_capability(
    path: &Path,
    expected_artifact_sha256: &str,
    expected_source_generation_sha256: &str,
) -> Result<
    (
        ExternalWorkerLease,
        CbmWorkerCapabilityReceipt,
        CbmWorkerCapabilityObservation,
    ),
    BridgeError,
> {
    if expected_artifact_sha256.len() != 64
        || !expected_artifact_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(envelope(
            "ASTRO_CBM_WORKER_EXPECTED_SHA256_INVALID",
            format!(
                "the expected worker artifact SHA-256 is not 64 lowercase hexadecimal bytes: {expected_artifact_sha256:?}"
            ),
            "Pass the exact lowercase SHA-256 from the immutable worker artifact publication receipt.",
        ));
    }
    if expected_source_generation_sha256.len() != 64
        || !expected_source_generation_sha256
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(envelope(
            "ASTRO_CBM_WORKER_EXPECTED_SOURCE_GENERATION_INVALID",
            format!(
                "the expected worker source generation is not 64 lowercase hexadecimal bytes: {expected_source_generation_sha256:?}"
            ),
            "Pass the exact source-generation SHA-256 from the frozen build publication receipt.",
        ));
    }
    if !path.is_absolute() {
        return Err(envelope(
            "ASTRO_CBM_WORKER_BINARY_PATH_NOT_ABSOLUTE",
            format!(
                "the external worker path {} is not absolute",
                path.display()
            ),
            "Pass the exact absolute path from the immutable shipping artifact publication receipt; executable search is not permitted.",
        ));
    }
    let mut lease = open_external_worker_lease(path)?;
    let artifact_sha256 = retained_file_sha256(&mut lease.file)?;
    if artifact_sha256 != expected_artifact_sha256 {
        return Err(envelope(
            "ASTRO_CBM_WORKER_ARTIFACT_SHA256_MISMATCH",
            format!(
                "the retained worker executable {} hashes to {artifact_sha256}, expected {expected_artifact_sha256}",
                path.display()
            ),
            "Select the exact immutable shipping artifact named by the publication receipt; do not bind a stale or substituted executable.",
        ));
    }
    let pid = std::process::id();
    let process_start = process_start_utc_ticks(pid).map_err(|error| {
        envelope(
            "ASTRO_CBM_WORKER_CAPABILITY_OWNER_IDENTITY_FAILED",
            format!("could not resolve capability verifier process {pid}: {error}"),
            "Inspect the exact verifier process identity and retry from one live native host.",
        )
    })?;
    let ordinal = WORKER_CAPABILITY_CHALLENGE_ORDINAL.fetch_add(1, Ordering::Relaxed);
    let challenge = format!("{pid:08x}-{process_start:016x}-{ordinal:016x}");
    // Launch through the normalized path read from the retained file handle,
    // while preserving the caller's original absolute spelling as argv[0].
    // `run_bounded_capability_process` converts this exact drive/UNC path to
    // extended-length lpApplicationName syntax before CreateProcessW.
    let application_path = Path::new(&lease.identity.final_handle_path);
    let BoundedCapabilityProcess {
        output,
        observation,
    } = run_bounded_capability_process(application_path, path, &challenge)?;
    let stdout_bytes = u64::try_from(output.stdout.len()).map_err(|_| {
        envelope(
            "ASTRO_CBM_WORKER_CAPABILITY_OBSERVATION_INVALID",
            "the retained capability stdout length does not fit in u64",
            "Stop startup and inspect the bounded capability reader; do not publish an incomplete parent observation.",
        )
    })?;
    let stderr_bytes = u64::try_from(output.stderr.len()).map_err(|_| {
        envelope(
            "ASTRO_CBM_WORKER_CAPABILITY_OBSERVATION_INVALID",
            "the retained capability stderr length does not fit in u64",
            "Stop startup and inspect the bounded capability reader; do not publish an incomplete parent observation.",
        )
    })?;
    let expected_empty_initial = CbmWorkerCapabilityJobSnapshot {
        accounting_before_total_processes: 0,
        accounting_before_active_processes: 0,
        accounting_before_total_terminated_processes: 0,
        total_processes: 0,
        active_processes: 0,
        total_terminated_processes: 0,
        assigned_processes: 0,
        listed_processes: 0,
        listed_process_id: None,
    };
    let expected_suspended = CbmWorkerCapabilityJobSnapshot {
        accounting_before_total_processes: 1,
        accounting_before_active_processes: 1,
        accounting_before_total_terminated_processes: 0,
        total_processes: 1,
        active_processes: 1,
        total_terminated_processes: 0,
        assigned_processes: 1,
        listed_processes: 1,
        listed_process_id: Some(observation.child_pid),
    };
    let expected_empty_terminal = CbmWorkerCapabilityJobSnapshot {
        accounting_before_total_processes: 1,
        accounting_before_active_processes: 0,
        accounting_before_total_terminated_processes: 0,
        total_processes: 1,
        active_processes: 0,
        total_terminated_processes: 0,
        assigned_processes: 0,
        listed_processes: 0,
        listed_process_id: None,
    };
    if observation.child_pid == 0
        || observation.primary_thread_id == 0
        || observation.resume_previous_suspend_count != 1
        || observation.timeout_ms == 0
        || observation.timeout_ms == u32::MAX
        || observation.elapsed_micros == 0
        || observation.job_empty_readbacks != 2
        || observation.job_pre_spawn_snapshot != expected_empty_initial
        || observation.job_suspended_snapshot != expected_suspended
        || observation.job_terminal_snapshot != expected_empty_terminal
        || observation.stdout_bytes != stdout_bytes
        || observation.stderr_bytes != stderr_bytes
    {
        return Err(envelope(
            "ASTRO_CBM_WORKER_CAPABILITY_OBSERVATION_INVALID",
            format!(
                "the bounded capability process returned an inconsistent parent observation: observation={observation:?}, retained_stdout_bytes={stdout_bytes}, retained_stderr_bytes={stderr_bytes}"
            ),
            "Stop startup and inspect the atomic Job/process/pipe terminal protocol; do not publish an internally inconsistent capability observation.",
        ));
    }
    if !output.status.success() {
        return Err(envelope(
            "ASTRO_CBM_WORKER_CAPABILITY_REFUSED",
            format!(
                "the retained worker executable {} refused the private capability probe (exit={:?}, stdout={:?}, stderr={:?})",
                path.display(),
                output.status.code(),
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            ),
            "Pass the matching shipping Astrolabe executable that implements the current private worker and progress schemas.",
        ));
    }
    if !output.stderr.is_empty() {
        return Err(envelope(
            "ASTRO_CBM_WORKER_CAPABILITY_STDERR",
            format!(
                "the retained worker executable {} emitted stderr during its capability probe: {:?}",
                path.display(),
                String::from_utf8_lossy(&output.stderr)
            ),
            "Repair the capability path so successful non-mutating probes emit exactly one stdout receipt and no diagnostics.",
        ));
    }
    let receipt_bytes = output.stdout.strip_suffix(b"\n").ok_or_else(|| {
        envelope(
            "ASTRO_CBM_WORKER_CAPABILITY_RECEIPT_FRAMING_INVALID",
            format!(
                "the worker capability receipt must end with exactly one LF byte: {:?}",
                String::from_utf8_lossy(&output.stdout)
            ),
            "Repair the private capability path so it emits exactly one compact JSON receipt followed by one LF byte.",
        )
    })?;
    // `stdout_bytes` deliberately includes the one required terminal LF; the
    // receipt payload alone is one byte shorter.
    let framed_receipt_bytes = u64::try_from(receipt_bytes.len())
        .ok()
        .and_then(|bytes| bytes.checked_add(1))
        .ok_or_else(|| {
            envelope(
                "ASTRO_CBM_WORKER_CAPABILITY_OBSERVATION_INVALID",
                "the framed capability receipt length does not fit in u64",
                "Stop startup and inspect the bounded capability output; do not publish an incomplete byte-count observation.",
            )
        })?;
    if observation.stdout_bytes != framed_receipt_bytes {
        return Err(envelope(
            "ASTRO_CBM_WORKER_CAPABILITY_OBSERVATION_INVALID",
            format!(
                "the capability stdout observation does not include exactly the JSON object and its terminal LF: observed={}, framed_receipt={framed_receipt_bytes}",
                observation.stdout_bytes
            ),
            "Stop startup and inspect the bounded capability framing; do not publish an observation that omits or adds output bytes.",
        ));
    }
    if receipt_bytes.is_empty()
        || receipt_bytes.first() != Some(&b'{')
        || receipt_bytes.last() != Some(&b'}')
        || receipt_bytes
            .iter()
            .any(|byte| *byte == b'\n' || *byte == b'\r')
    {
        return Err(envelope(
            "ASTRO_CBM_WORKER_CAPABILITY_RECEIPT_FRAMING_INVALID",
            format!(
                "the worker capability receipt is not exactly one JSON object line: {:?}",
                String::from_utf8_lossy(&output.stdout)
            ),
            "Repair the private capability path so it emits exactly one compact JSON receipt followed by one LF byte.",
        ));
    }
    let stdout = std::str::from_utf8(receipt_bytes).map_err(|error| {
        envelope(
            "ASTRO_CBM_WORKER_CAPABILITY_UTF8_INVALID",
            format!("the worker capability receipt is not UTF-8: {error}"),
            "Use the matching shipping Astrolabe executable and inspect its capability output bytes.",
        )
    })?;
    let receipt: CbmWorkerCapabilityReceipt = serde_json::from_str(stdout).map_err(|error| {
        envelope(
            "ASTRO_CBM_WORKER_CAPABILITY_RECEIPT_INVALID",
            format!("the worker capability receipt is not the required JSON schema: {error}"),
            "Use the matching shipping Astrolabe executable and inspect its capability receipt.",
        )
    })?;
    let expected_entrypoint = [
        "cli",
        "--index-worker",
        "index_repository",
        "--args-file",
        "{args_path}",
        "--response-out",
        "{response_path}",
        "--worker-progress-out",
        "{progress_path}",
        "--worker-progress-attempt",
        "{attempt_sha256}",
    ];
    if receipt.schema != ASTRO_INDEX_WORKER_CAPABILITY_SCHEMA
        || receipt.challenge != challenge
        || receipt.worker_argv_schema != ASTRO_INDEX_WORKER_ARGV_SCHEMA
        || receipt.progress_schema != ASTRO_INDEX_WORKER_PROGRESS_SCHEMA
        || receipt.progress_schema_version != 1
        || receipt
            .worker_argv_template
            .iter()
            .map(String::as_str)
            .collect::<Vec<_>>()
            != expected_entrypoint
        || receipt.worker_cache_arg != "_astrolabe_worker_cache_dir"
        || receipt.transition_grant_arg != "_astrolabe_project_transition_writer"
        || receipt.package_version != env!("CARGO_PKG_VERSION")
        || receipt.source_generation_schema != ASTRO_WORKER_SOURCE_GENERATION_SCHEMA
        || receipt.source_generation_sha256 != expected_source_generation_sha256
        || receipt.artifact_identity != lease.identity
    {
        return Err(envelope(
            "ASTRO_CBM_WORKER_CAPABILITY_MISMATCH",
            format!(
                "the worker capability receipt from {} does not bind the exact retained artifact and current private protocols: {receipt:?}",
                path.display()
            ),
            "Use the exact shipping Astrolabe executable built from this source generation; do not run a stale or embedding image.",
        ));
    }
    Ok((lease, receipt, observation))
}

/// Read back the exact native worker executable bound for this process.
/// Absence is explicit so callers can distinguish an unconfigured host from an
/// unreadable or malformed native path.
pub fn configured_cbm_host_binary_path() -> Result<Option<PathBuf>, BridgeError> {
    // SAFETY: the native getter returns either NULL or one process-lifetime
    // immutable NUL-terminated string published with release/acquire ordering.
    let configured = unsafe { cbm_sys::cbm_http_server_binary_path() };
    if configured.is_null() {
        return Ok(None);
    }
    // SAFETY: non-NULL is the immutable native string described above.
    let path = unsafe { CStr::from_ptr(configured) }.to_str()?;
    Ok(Some(PathBuf::from(path)))
}

fn worker_binary_status_text(
    status: cbm_sys::cbm_worker_binary_status_t,
    selector: unsafe extern "C" fn(c_int) -> *const c_char,
    fallback: &str,
) -> String {
    // SAFETY: the selector accepts every integer status and returns a static
    // NUL-terminated diagnostic string.
    let value = unsafe { selector(status) };
    if value.is_null() {
        return fallback.to_string();
    }
    // SAFETY: non-NULL selector results are process-lifetime static C strings.
    unsafe { CStr::from_ptr(value) }
        .to_string_lossy()
        .into_owned()
}

fn worker_binary_status_error(
    status: cbm_sys::cbm_worker_binary_status_t,
    native_error: c_ulong,
    path: Option<&Path>,
) -> BridgeError {
    let code = worker_binary_status_text(
        status,
        cbm_sys::cbm_http_server_binary_status_code,
        "CBM_WORKER_BINARY_UNKNOWN_STATUS",
    );
    let base_message = worker_binary_status_text(
        status,
        cbm_sys::cbm_http_server_binary_status_message,
        "the worker executable binding returned an unknown status",
    );
    let remediation = worker_binary_status_text(
        status,
        cbm_sys::cbm_http_server_binary_status_remediation,
        "report the unknown status and do not enable supervised indexing",
    );
    let context = path
        .map(|path| format!(" path={:?}", path))
        .unwrap_or_default();
    envelope(
        code,
        format!("{base_message}; status={status}; native_error={native_error};{context}"),
        remediation,
    )
}

fn prepare_cbm_host_binding() -> Result<(), BridgeError> {
    // Refuse a store-relocating environment before any process-global logging,
    // profile, host-role, or memory initialization is changed (#194/#232).
    validate_cbm_store_env(
        std::env::var("CBM_CACHE_DIR").ok().as_deref(),
        std::env::var("HOME").ok().as_deref(),
        std::env::var("USERPROFILE").ok().as_deref(),
    )?;
    initialize_cbm_allocator()
}

/// Bind the operating-system current process image as the sole worker binary.
/// No argv/PATH spelling participates in this production authority.
pub fn bind_cbm_host_self() -> Result<PathBuf, BridgeError> {
    prepare_cbm_host_binding()?;
    let requested = std::env::current_exe().map_err(|error| {
        envelope(
            "ASTRO_CBM_HOST_CURRENT_EXE_FAILED",
            format!("the operating system did not expose the current process image: {error}"),
            "Launch the existing ordinary shipping Astrolabe executable directly and inspect the operating-system error.",
        )
    })?;
    let requested_identity = capture_windows_file_identity(&requested).map_err(|error| {
        envelope(
            "ASTRO_CBM_HOST_CURRENT_EXE_IDENTITY_FAILED",
            format!("the current process image failed independent identity readback: {error}"),
            "Launch one ordinary non-reparse shipping Astrolabe executable and inspect the reported filesystem operation.",
        )
    })?;
    let mut native_error: c_ulong = 0;
    // SAFETY: the native function has one valid writable error output and uses
    // the operating system's current-image authority internally.
    let status = unsafe { cbm_sys::cbm_http_server_bind_self_binary(&mut native_error) };
    if status != cbm_sys::cbm_worker_binary_status_t_CBM_WORKER_BINARY_OK {
        return Err(worker_binary_status_error(
            status,
            native_error,
            Some(&requested),
        ));
    }
    let observed = configured_cbm_host_binary_path()?.ok_or_else(|| {
        envelope(
            "ASTRO_CBM_HOST_BINARY_PATH_READBACK_FAILED",
            "the native self binding reported success but its immutable path getter is absent",
            "Stop startup and inspect the native binding publication before enabling indexing.",
        )
    })?;
    let observed_identity = capture_windows_file_identity(&observed).map_err(|error| {
        envelope(
            "ASTRO_CBM_HOST_BINARY_IDENTITY_READBACK_FAILED",
            format!(
                "the bound self path {} failed independent identity readback: {error}",
                observed.display()
            ),
            "Stop startup and inspect the retained worker file identity before enabling indexing.",
        )
    })?;
    if observed_identity != requested_identity {
        return Err(envelope(
            "ASTRO_CBM_HOST_BINARY_IDENTITY_READBACK_MISMATCH",
            format!(
                "the native bound identity {observed_identity:?} does not equal the operating-system current image {requested_identity:?}"
            ),
            "Stop startup; do not enable indexing until one exact current-image identity is bound and read back.",
        ));
    }
    Ok(observed)
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CbmVerifiedWorkerBinding {
    pub configured_path: PathBuf,
    pub capability: CbmWorkerCapabilityReceipt,
    pub capability_observation: CbmWorkerCapabilityObservation,
    pub retained_identity: WindowsFileIdentity,
    pub artifact_sha256: String,
}

/// Bind an external shipping worker only after its exact retained file answers
/// the current private argv/progress capability challenge without mutation.
pub fn bind_verified_external_cbm_worker(
    path: &Path,
    expected_artifact_sha256: &str,
    expected_source_generation_sha256: &str,
) -> Result<CbmVerifiedWorkerBinding, BridgeError> {
    prepare_cbm_host_binding()?;
    let (lease, capability, capability_observation) = verify_external_worker_capability(
        path,
        expected_artifact_sha256,
        expected_source_generation_sha256,
    )?;
    let path_text = path.to_str().ok_or_else(|| {
        envelope(
            "ASTRO_CBM_WORKER_BINARY_PATH_UTF8_INVALID",
            format!("the external worker path {path:?} is not valid UTF-8"),
            "Pass the exact absolute UTF-8 path to the shipping Astrolabe executable.",
        )
    })?;
    let path_c = CString::new(path_text)?;
    let mut native_error: c_ulong = 0;
    // SAFETY: the C string and writable native-error output remain live for the
    // call. `lease` simultaneously denies write/delete sharing over these bytes.
    let status = unsafe {
        cbm_sys::cbm_http_server_bind_explicit_binary(path_c.as_ptr(), &mut native_error)
    };
    if status != cbm_sys::cbm_worker_binary_status_t_CBM_WORKER_BINARY_OK {
        return Err(worker_binary_status_error(status, native_error, Some(path)));
    }
    let observed = configured_cbm_host_binary_path()?.ok_or_else(|| {
        envelope(
            "ASTRO_CBM_HOST_BINARY_PATH_READBACK_FAILED",
            "the verified external binding reported success but its immutable path getter is absent",
            "Stop startup and inspect the native binding publication before enabling indexing.",
        )
    })?;
    let observed_identity = capture_windows_file_identity(&observed).map_err(|error| {
        envelope(
            "ASTRO_CBM_WORKER_BINARY_IDENTITY_READBACK_FAILED",
            format!(
                "the bound external worker {} failed identity readback: {error}",
                observed.display()
            ),
            "Stop startup and inspect the retained worker identity before enabling indexing.",
        )
    })?;
    if observed_identity != lease.identity {
        return Err(envelope(
            "ASTRO_CBM_WORKER_BINARY_IDENTITY_READBACK_MISMATCH",
            format!(
                "the native bound identity {observed_identity:?} does not equal the capability-held identity {:?}",
                lease.identity
            ),
            "Stop startup; do not enable indexing until the capability and native retained handle bind one exact file identity.",
        ));
    }
    Ok(CbmVerifiedWorkerBinding {
        configured_path: observed,
        capability,
        capability_observation,
        retained_identity: observed_identity,
        artifact_sha256: expected_artifact_sha256.to_string(),
    })
}

pub fn run_cbm_installer_command(command: &str, args: &[String]) -> Result<i32, BridgeError> {
    initialize_cbm_allocator()?;
    let argc = c_int::try_from(args.len()).map_err(|_| {
        envelope(
            "ASTRO_CBM_INSTALLER_ARGC",
            format!("installer command {command} received too many arguments"),
            "Reduce command-line argument count before invoking the CBM installer surface.",
        )
    })?;
    let c_args = args
        .iter()
        .map(|arg| CString::new(arg.as_str()))
        .collect::<Result<Vec<_>, _>>()?;
    let mut argv = c_args
        .iter()
        .map(|arg| arg.as_ptr().cast_mut())
        .collect::<Vec<_>>();

    let rc = unsafe {
        match command {
            "install" => cbm_sys::cbm_cmd_install(argc, argv.as_mut_ptr()),
            "uninstall" => cbm_sys::cbm_cmd_uninstall(argc, argv.as_mut_ptr()),
            "update" => cbm_sys::cbm_cmd_update(argc, argv.as_mut_ptr()),
            other => {
                return Err(envelope(
                    "ASTRO_CBM_INSTALLER_COMMAND",
                    format!("unsupported CBM installer command {other:?}"),
                    "Use install, uninstall, or update.",
                ));
            }
        }
    };
    Ok(rc)
}

pub fn cbm_install_plan_json(home: &str, binary_path: &str) -> Result<String, BridgeError> {
    initialize_cbm_allocator()?;
    let home = CString::new(home)?;
    let binary_path = CString::new(binary_path)?;
    unsafe {
        take_c_string(cbm_sys::cbm_build_install_plan_json(
            home.as_ptr(),
            binary_path.as_ptr(),
        ))
    }
}

fn apply_cbm_log_mode(log_mode: CbmLogMode, profile_active: bool) {
    // SAFETY: these are process-global startup settings. Binary binding and its
    // independent readback have already completed before this helper is called.
    unsafe {
        match log_mode {
            CbmLogMode::Default => {}
            CbmLogMode::CliWarnFloor => {
                if !profile_active {
                    let floor =
                        c_int::try_from(astrolabe_domain::knobs::cli_stderr_log_level_floor())
                            .unwrap_or(cbm_sys::CBMLogLevel_CBM_LOG_WARN);
                    cbm_sys::cbm_log_set_level(floor);
                }
            }
            CbmLogMode::Silent => {
                cbm_sys::cbm_log_set_level(cbm_sys::CBMLogLevel_CBM_LOG_NONE);
                cbm_sys::cbm_log_set_sink_ex(
                    Some(cbm_log_silent_sink),
                    cbm_sys::CBMLogSinkMode_CBM_LOG_SINK_REPLACE,
                );
            }
        }
    }
}

fn activate_cbm_memory() {
    // SAFETY: version and memory initialization are process-global startup
    // operations and take no caller-owned pointers.
    unsafe {
        cbm_sys::cbm_cli_set_version(c"dev".as_ptr());
        let info = cbm_sys::cbm_system_info();
        let ram_fraction = cbm_sys::cbm_mem_ram_fraction_for_total(info.total_ram);
        cbm_sys::cbm_mem_init(ram_fraction);
    }
}

/// Complete host-role activation after a successful exact binary bind and after
/// the caller has installed its tracing/log route.
pub fn activate_cbm_host_process(
    log_mode: CbmLogMode,
    profile_active: bool,
) -> Result<(), BridgeError> {
    if configured_cbm_host_binary_path()?.is_none() {
        return Err(envelope(
            "CBM_INDEX_WORKER_BINARY_PATH_UNBOUND",
            "host activation was requested before an exact worker executable identity was bound",
            "Bind and independently read back the self or capability-verified worker identity before host activation.",
        ));
    }
    apply_cbm_log_mode(log_mode, profile_active);
    // SAFETY: the host-role flag is one process-global startup mutation with no
    // caller-owned pointers. It follows the mandatory binding readback above.
    unsafe { cbm_sys::cbm_index_supervisor_mark_host() };
    activate_cbm_memory();
    Ok(())
}

/// Validate non-host process prerequisites before any logging/profile mutation.
pub fn prepare_cbm_non_host_process() -> Result<(), BridgeError> {
    prepare_cbm_host_binding()
}

/// Initialize libcbm for a process that may perform in-process reads but is not
/// authorized to spawn supervised index workers (for example hook augmentation).
pub fn activate_cbm_non_host_process(
    log_mode: CbmLogMode,
    profile_active: bool,
) -> Result<(), BridgeError> {
    apply_cbm_log_mode(log_mode, profile_active);
    activate_cbm_memory();
    Ok(())
}

fn initialize_bound_cbm_host(log_mode: CbmLogMode) -> Result<(), BridgeError> {
    bind_cbm_host_self()?;
    initialize_cbm_log_configuration()?;
    let profile_active = initialize_cbm_profile_mode()?;
    activate_cbm_host_process(log_mode, profile_active)
}

/// Initialize a normal Astrolabe host from the operating-system current image.
pub fn initialize_cbm_host_process() -> Result<(), BridgeError> {
    initialize_bound_cbm_host(CbmLogMode::Default)
}

/// Initialize a CLI host from the operating-system current image.
pub fn initialize_cbm_host_process_cli() -> Result<(), BridgeError> {
    initialize_bound_cbm_host(CbmLogMode::CliWarnFloor)
}

/// Capability-check, retain, bind, and activate an external shipping worker.
pub fn initialize_cbm_host_process_with_verified_worker(
    path: &Path,
    expected_artifact_sha256: &str,
    expected_source_generation_sha256: &str,
) -> Result<CbmVerifiedWorkerBinding, BridgeError> {
    let binding = bind_verified_external_cbm_worker(
        path,
        expected_artifact_sha256,
        expected_source_generation_sha256,
    )?;
    initialize_cbm_log_configuration()?;
    let profile_active = initialize_cbm_profile_mode()?;
    activate_cbm_host_process(CbmLogMode::Default, profile_active)?;
    Ok(binding)
}

unsafe extern "C" fn cbm_log_silent_sink(_line: *const c_char) {}

pub struct CbmIndexWorkerRole {
    _response_out: Option<CString>,
    _progress_out: Option<CString>,
    _progress_attempt: Option<CString>,
    _transition_writer_project: Option<CString>,
}

impl CbmIndexWorkerRole {
    pub fn activate(
        response_out: Option<&str>,
        progress_out: Option<&str>,
        progress_attempt: Option<&str>,
        transition_writer_project: Option<&str>,
    ) -> Result<Self, BridgeError> {
        initialize_cbm_allocator()?;
        let response_out = response_out.map(CString::new).transpose()?;
        let progress_out = progress_out.map(CString::new).transpose()?;
        let progress_attempt = progress_attempt.map(CString::new).transpose()?;
        let transition_writer_project = transition_writer_project.map(CString::new).transpose()?;
        // SAFETY: CBM copies response_out into process-global worker state.
        unsafe {
            let worker_role_rc = cbm_sys::cbm_index_set_worker_role(
                true,
                response_out
                    .as_ref()
                    .map_or(ptr::null(), |path| path.as_ptr()),
                progress_out
                    .as_ref()
                    .map_or(ptr::null(), |path| path.as_ptr()),
                progress_attempt
                    .as_ref()
                    .map_or(ptr::null(), |attempt| attempt.as_ptr()),
            );
            if worker_role_rc != 0 {
                return Err(envelope(
                    "ASTRO_INDEX_WORKER_PROGRESS_CONFIG_FAILED",
                    "libcbm refused the supervised worker semantic-progress binding",
                    "Start index_repository through the installed Astrolabe supervisor and preserve its worker workspace diagnostic.",
                ));
            }
            cbm_sys::cbm_index_set_transition_writer_project(
                transition_writer_project
                    .as_ref()
                    .map_or(ptr::null(), |project| project.as_ptr()),
            );
        }
        Ok(Self {
            _response_out: response_out,
            _progress_out: progress_out,
            _progress_attempt: progress_attempt,
            _transition_writer_project: transition_writer_project,
        })
    }

    pub fn complete_progress(&self) -> Result<(), BridgeError> {
        // SAFETY: activation configured the process-global writer. The C API
        // is a no-op when this worker role has no supervised progress channel.
        let rc = unsafe { cbm_sys::cbm_index_worker_progress_complete() };
        if rc != 0 {
            return Err(envelope(
                "ASTRO_INDEX_WORKER_PROGRESS_COMPLETE_FAILED",
                "the worker response was written but its terminal semantic-progress record could not be published",
                "Preserve the worker workspace and inspect the progress-stream diagnostic before retrying.",
            ));
        }
        Ok(())
    }
}

impl Drop for CbmIndexWorkerRole {
    fn drop(&mut self) {
        // SAFETY: resetting the process-global worker role has no preconditions.
        unsafe {
            cbm_sys::cbm_index_set_transition_writer_project(ptr::null());
            let _ =
                cbm_sys::cbm_index_set_worker_role(false, ptr::null(), ptr::null(), ptr::null());
        }
    }
}

unsafe extern "C" fn cbm_log_tracing_sink(line: *const c_char) {
    if line.is_null() {
        return;
    }
    drop(std::panic::catch_unwind(AssertUnwindSafe(|| {
        // SAFETY: CBM calls the sink with a NUL-terminated line valid for the call.
        let line = unsafe { CStr::from_ptr(line) };
        if CBM_JSON_LOG_MODE.load(Ordering::Acquire) {
            // JSON is already the authoritative native byte record. Sending it
            // through a human-readable tracing formatter would turn it into
            // `ERROR {json}` and destroy newline-delimited JSON; decoding it first
            // would also make preservation lossy. libcbm invokes sinks while
            // holding its log mutex, while stderr's process-global lock prevents
            // same-process Rust events from interleaving this record.
            let mut stderr = std::io::stderr().lock();
            let _ = stderr
                .write_all(line.to_bytes())
                .and_then(|()| stderr.write_all(b"\n"));
            return;
        }

        let line = line.to_string_lossy();
        if line.starts_with("level=error") {
            tracing::error!(target: "cbm", "{line}");
        } else if line.starts_with("level=warn") {
            tracing::warn!(target: "cbm", "{line}");
        } else if line.starts_with("level=debug") {
            tracing::debug!(target: "cbm", "{line}");
        } else {
            tracing::info!(target: "cbm", "{line}");
        }
    })));
}

#[cfg(unix)]
pub fn parent_process_id() -> Option<u32> {
    // SAFETY: getppid has no preconditions and does not write through pointers.
    Some(unsafe { libc::getppid() as u32 })
}

#[cfg(windows)]
pub fn parent_process_id() -> Option<u32> {
    windows_watchdog::parent_process_id()
}

#[cfg(windows)]
pub fn process_start_utc_ticks(pid: u32) -> Result<u64, String> {
    windows_watchdog::process_start_utc_ticks(pid)
}

/// Exact Windows process-generation probe used by durable recovery protocols.
///
/// A numeric PID is not an identity after process exit. Callers persist both
/// the PID and creation FILETIME ticks, then use this result to distinguish an
/// absent generation from a matching live owner or a reused PID.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessGenerationState {
    Absent,
    Matching,
    Reused { actual_start_utc_ticks: u64 },
}

#[cfg(windows)]
pub fn process_generation_state(
    pid: u32,
    expected_start_utc_ticks: u64,
) -> Result<ProcessGenerationState, String> {
    windows_watchdog::process_generation_state(pid, expected_start_utc_ticks)
}

#[cfg(not(any(unix, windows)))]
pub fn parent_process_id() -> Option<u32> {
    None
}

#[cfg(not(windows))]
pub fn process_start_utc_ticks(_pid: u32) -> Result<u64, String> {
    Err(
        "ASTRO_PROCESS_GENERATION_UNSUPPORTED: exact process creation ticks require Windows"
            .to_string(),
    )
}

#[cfg(not(windows))]
pub fn process_generation_state(
    _pid: u32,
    _expected_start_utc_ticks: u64,
) -> Result<ProcessGenerationState, String> {
    Err(
        "ASTRO_PROCESS_GENERATION_UNSUPPORTED: exact process-generation probes require Windows"
            .to_string(),
    )
}

/// Outcome of a bounded wait for the parent process to exit (#253).
///
/// Windows has no `getppid` reparenting signal (it never reparents an orphan), so the
/// Unix ppid-change watchdog cannot work here. Instead the watchdog opens a `SYNCHRONIZE`
/// handle to the parent and waits on it: a process handle becomes signaled when the
/// process exits. A wait that cannot be performed is [`ParentWaitOutcome::Failed`], never
/// silently treated as "still alive" — a watchdog that cannot watch must fail closed.
#[cfg(windows)]
#[derive(Debug)]
pub enum ParentWaitOutcome {
    /// The parent process has exited (its handle signaled); the child should self-terminate.
    Exited,
    /// The parent is still alive; the bounded wait elapsed without the handle signaling.
    StillAlive,
    /// The wait itself failed; the caller must fail closed rather than assume liveness.
    Failed(String),
}

#[cfg(windows)]
pub use windows_watchdog::ParentDeathWatch;

#[cfg(windows)]
mod windows_watchdog {
    use std::ffi::c_void;

    type Handle = *mut c_void;
    type Ntstatus = i32;

    // Fixed, stable layout (documented in winternl.h); Rust's own std test suite declares
    // it identically. Only `inherited_from_unique_process_id` (the parent PID) is read.
    #[repr(C)]
    struct ProcessBasicInformation {
        exit_status: Ntstatus,
        peb_base_address: *mut c_void,
        affinity_mask: usize,
        base_priority: i32,
        unique_process_id: usize,
        inherited_from_unique_process_id: usize,
    }

    #[repr(C)]
    struct FileTime {
        low: u32,
        high: u32,
    }

    const PROCESS_BASIC_INFORMATION_CLASS: i32 = 0;
    const SYNCHRONIZE: u32 = 0x0010_0000;
    const PROCESS_QUERY_LIMITED_INFORMATION: u32 = 0x0000_1000;
    const WAIT_OBJECT_0: u32 = 0x0000_0000;
    const WAIT_TIMEOUT: u32 = 0x0000_0102;
    const WAIT_FAILED: u32 = 0xFFFF_FFFF;

    // NtQueryInformationProcess is the documented route to a process's parent PID
    // (PROCESS_BASIC_INFORMATION.InheritedFromUniqueProcessId); Windows exposes no getppid.
    #[link(name = "ntdll")]
    unsafe extern "system" {
        fn NtQueryInformationProcess(
            handle: Handle,
            class: i32,
            info: *mut c_void,
            len: u32,
            ret_len: *mut u32,
        ) -> Ntstatus;
    }

    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn GetCurrentProcess() -> Handle;
        fn OpenProcess(access: u32, inherit: i32, pid: u32) -> Handle;
        fn WaitForSingleObject(handle: Handle, millis: u32) -> u32;
        fn GetProcessTimes(
            handle: Handle,
            creation: *mut FileTime,
            exit: *mut FileTime,
            kernel: *mut FileTime,
            user: *mut FileTime,
        ) -> i32;
        fn GetExitCodeProcess(handle: Handle, exit_code: *mut u32) -> i32;
        fn CloseHandle(handle: Handle) -> i32;
        fn GetLastError() -> u32;
    }

    pub(crate) fn parent_process_id() -> Option<u32> {
        let mut info = ProcessBasicInformation {
            exit_status: 0,
            peb_base_address: std::ptr::null_mut(),
            affinity_mask: 0,
            base_priority: 0,
            unique_process_id: 0,
            inherited_from_unique_process_id: 0,
        };
        let mut ret_len: u32 = 0;
        // SAFETY: GetCurrentProcess returns the current-process pseudo-handle (no lifetime
        // to manage). We pass a correctly sized, fully initialized PROCESS_BASIC_INFORMATION
        // and its exact size; the call writes only within that buffer.
        let status = unsafe {
            NtQueryInformationProcess(
                GetCurrentProcess(),
                PROCESS_BASIC_INFORMATION_CLASS,
                std::ptr::from_mut(&mut info).cast(),
                std::mem::size_of::<ProcessBasicInformation>() as u32,
                &mut ret_len,
            )
        };
        if status != 0 {
            return None;
        }
        let ppid = info.inherited_from_unique_process_id as u32;
        if ppid == 0 { None } else { Some(ppid) }
    }

    pub(crate) fn process_start_utc_ticks(pid: u32) -> Result<u64, String> {
        // SAFETY: OpenProcess writes through no pointers; null is checked before use.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            // SAFETY: GetLastError has no preconditions.
            let code = unsafe { GetLastError() };
            return Err(format!(
                "ASTRO_PROCESS_GENERATION_OPEN_FAILED: OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) for pid {pid} failed (native_error={code})"
            ));
        }
        let mut creation = FileTime { low: 0, high: 0 };
        let mut exit = FileTime { low: 0, high: 0 };
        let mut kernel = FileTime { low: 0, high: 0 };
        let mut user = FileTime { low: 0, high: 0 };
        // SAFETY: handle is live and each out pointer names a correctly sized FILETIME.
        let ok =
            unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) };
        if ok == 0 {
            // SAFETY: GetLastError is read before closing the process handle.
            let code = unsafe { GetLastError() };
            // SAFETY: handle came from OpenProcess and is closed exactly once here.
            unsafe { CloseHandle(handle) };
            return Err(format!(
                "ASTRO_PROCESS_GENERATION_QUERY_FAILED: GetProcessTimes for pid {pid} failed (native_error={code})"
            ));
        }
        // SAFETY: handle came from OpenProcess and is closed exactly once here.
        unsafe { CloseHandle(handle) };
        Ok((u64::from(creation.high) << 32) | u64::from(creation.low))
    }

    pub(crate) fn process_generation_state(
        pid: u32,
        expected_start_utc_ticks: u64,
    ) -> Result<super::ProcessGenerationState, String> {
        // ERROR_INVALID_PARAMETER means no process object is addressable by
        // this PID. A terminated object may still be openable while another
        // handle retains it, so creation identity and GetExitCodeProcess below
        // jointly decide whether the exact generation is still active. Every
        // other open/query failure is unevaluable and remains preserving.
        const ERROR_INVALID_PARAMETER: u32 = 87;
        // SAFETY: OpenProcess writes through no pointers; null is checked.
        let handle = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
        if handle.is_null() {
            // SAFETY: GetLastError has no preconditions.
            let code = unsafe { GetLastError() };
            if code == ERROR_INVALID_PARAMETER {
                return Ok(super::ProcessGenerationState::Absent);
            }
            return Err(format!(
                "ASTRO_PROCESS_GENERATION_OPEN_FAILED: OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION) for pid {pid} failed (native_error={code})"
            ));
        }
        let mut creation = FileTime { low: 0, high: 0 };
        let mut exit = FileTime { low: 0, high: 0 };
        let mut kernel = FileTime { low: 0, high: 0 };
        let mut user = FileTime { low: 0, high: 0 };
        // SAFETY: handle is live and each out pointer names a FILETIME.
        let ok =
            unsafe { GetProcessTimes(handle, &mut creation, &mut exit, &mut kernel, &mut user) };
        if ok == 0 {
            // SAFETY: read the native error before closing the valid handle.
            let code = unsafe { GetLastError() };
            // SAFETY: handle came from OpenProcess and is closed exactly once.
            unsafe { CloseHandle(handle) };
            return Err(format!(
                "ASTRO_PROCESS_GENERATION_QUERY_FAILED: GetProcessTimes for pid {pid} failed (native_error={code})"
            ));
        }
        let mut exit_code = 0_u32;
        // SAFETY: handle is still live and exit_code names one initialized u32.
        let exit_code_ok = unsafe { GetExitCodeProcess(handle, &mut exit_code) };
        if exit_code_ok == 0 {
            // SAFETY: read the native error before closing the valid handle.
            let code = unsafe { GetLastError() };
            // SAFETY: handle came from OpenProcess and is closed exactly once.
            unsafe { CloseHandle(handle) };
            return Err(format!(
                "ASTRO_PROCESS_GENERATION_EXIT_QUERY_FAILED: GetExitCodeProcess for pid {pid} failed (native_error={code})"
            ));
        }
        // SAFETY: handle came from OpenProcess and is closed exactly once.
        unsafe { CloseHandle(handle) };
        let actual_start_utc_ticks = (u64::from(creation.high) << 32) | u64::from(creation.low);
        const STILL_ACTIVE: u32 = 259;
        if actual_start_utc_ticks != expected_start_utc_ticks {
            Ok(super::ProcessGenerationState::Reused {
                actual_start_utc_ticks,
            })
        } else if exit_code == STILL_ACTIVE {
            Ok(super::ProcessGenerationState::Matching)
        } else {
            Ok(super::ProcessGenerationState::Absent)
        }
    }

    /// A `SYNCHRONIZE` handle to the parent process. Its wait state becomes signaled when
    /// the parent exits, so a bounded [`ParentDeathWatch::wait`] on it detects parent death
    /// near-instantly without polling.
    pub struct ParentDeathWatch {
        handle: Handle,
    }

    // SAFETY: a Windows HANDLE is an opaque kernel-object reference that may be used from
    // any thread; this value is only ever waited on / closed from the single watchdog
    // thread that owns it.
    unsafe impl Send for ParentDeathWatch {}

    impl ParentDeathWatch {
        /// Opens a `SYNCHRONIZE` handle to `parent_pid`. Fails closed with a coded message
        /// if the process cannot be opened (typically because the parent is already gone).
        pub fn open(parent_pid: u32) -> Result<Self, String> {
            // SAFETY: OpenProcess writes through no caller pointers; a null return is the
            // documented failure signal, which we check before constructing the wrapper.
            let handle = unsafe { OpenProcess(SYNCHRONIZE, 0, parent_pid) };
            if handle.is_null() {
                // SAFETY: GetLastError has no preconditions.
                let code = unsafe { GetLastError() };
                return Err(format!(
                    "ASTRO_WATCHDOG_PARENT_OPEN: OpenProcess(SYNCHRONIZE) for parent pid \
                     {parent_pid} failed (GetLastError={code}); the parent may already have exited"
                ));
            }
            Ok(Self { handle })
        }

        /// Waits up to `timeout_ms` for the parent to exit. Returns immediately with
        /// [`ParentWaitOutcome::Exited`] once the handle signals.
        pub fn wait(&self, timeout_ms: u32) -> super::ParentWaitOutcome {
            // SAFETY: self.handle is a live SYNCHRONIZE handle owned by this value.
            let rc = unsafe { WaitForSingleObject(self.handle, timeout_ms) };
            match rc {
                WAIT_OBJECT_0 => super::ParentWaitOutcome::Exited,
                WAIT_TIMEOUT => super::ParentWaitOutcome::StillAlive,
                WAIT_FAILED => {
                    // SAFETY: GetLastError has no preconditions.
                    let code = unsafe { GetLastError() };
                    super::ParentWaitOutcome::Failed(format!(
                        "ASTRO_WATCHDOG_WAIT: WaitForSingleObject on the parent handle failed \
                         (GetLastError={code})"
                    ))
                }
                other => super::ParentWaitOutcome::Failed(format!(
                    "ASTRO_WATCHDOG_WAIT: WaitForSingleObject returned unexpected code {other:#010x}"
                )),
            }
        }
    }

    impl Drop for ParentDeathWatch {
        fn drop(&mut self) {
            // SAFETY: self.handle came from OpenProcess and is closed exactly once, here.
            unsafe {
                CloseHandle(self.handle);
            }
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ErrorEnvelope {
    pub code: String,
    pub message: String,
    pub remediation: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stderr: Option<String>,
}

impl ErrorEnvelope {
    pub fn new(
        code: impl Into<String>,
        message: impl Into<String>,
        remediation: impl Into<String>,
    ) -> Self {
        Self {
            code: code.into(),
            message: message.into(),
            remediation: remediation.into(),
            stderr: None,
        }
    }

    pub fn with_stderr(mut self, stderr: impl Into<String>) -> Self {
        self.stderr = Some(stderr.into());
        self
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct BridgeError {
    envelope: ErrorEnvelope,
}

impl BridgeError {
    pub fn new(envelope: ErrorEnvelope) -> Self {
        Self { envelope }
    }

    pub fn envelope(&self) -> &ErrorEnvelope {
        &self.envelope
    }

    pub fn into_envelope(self) -> ErrorEnvelope {
        self.envelope
    }
}

impl fmt::Display for BridgeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{}: {}; remediation: {}",
            self.envelope.code, self.envelope.message, self.envelope.remediation
        )?;
        if let Some(stderr) = self
            .envelope
            .stderr
            .as_deref()
            .filter(|stderr| !stderr.is_empty())
        {
            write!(f, "; stderr:\n{stderr}")?;
        }
        Ok(())
    }
}

impl Error for BridgeError {}

impl From<NulError> for BridgeError {
    fn from(err: NulError) -> Self {
        envelope(
            "ASTRO_CBM_NUL_BYTE",
            format!(
                "string argument contains an interior NUL byte at {}",
                err.nul_position()
            ),
            "Validate UTF-8 text before passing it through the C boundary.",
        )
    }
}

impl From<std::str::Utf8Error> for BridgeError {
    fn from(err: std::str::Utf8Error) -> Self {
        envelope(
            "ASTRO_CBM_INVALID_UTF8",
            format!("CBM returned non-UTF-8 text: {err}"),
            "Keep boundary payloads UTF-8; Windows wide-path conversion remains inside libcbm.",
        )
    }
}

impl From<std::string::FromUtf8Error> for BridgeError {
    fn from(err: std::string::FromUtf8Error) -> Self {
        envelope(
            "ASTRO_CBM_INVALID_UTF8",
            format!("CBM returned non-UTF-8 text: {}", err.utf8_error()),
            "Keep boundary payloads UTF-8; Windows wide-path conversion remains inside libcbm.",
        )
    }
}

fn envelope(
    code: impl Into<String>,
    message: impl Into<String>,
    remediation: impl Into<String>,
) -> BridgeError {
    BridgeError::new(ErrorEnvelope::new(code, message, remediation))
}

fn internal(message: impl Into<String>) -> BridgeError {
    envelope(
        "ASTRO_CBM_INTERNAL",
        message,
        "Capture the failing input and inspect the libcbm stderr/log output.",
    )
}

fn required_borrowed_c_string(ptr: *const c_char, field: &str) -> Result<String, BridgeError> {
    if ptr.is_null() {
        return Err(envelope(
            "ASTRO_CBM_NULL_FIELD",
            format!("CBM returned NULL for required field {field}"),
            "Treat this as FFI contract drift and keep the raw result for debugging.",
        ));
    }
    // SAFETY: callers pass borrowed CBM strings that are NUL-terminated and
    // valid for the duration of the enclosing FFI callback or owner call.
    Ok(unsafe { CStr::from_ptr(ptr) }.to_str()?.to_owned())
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct Language(cbm_sys::CBMLanguage);

impl Language {
    pub const C: Self = Self(cbm_sys::CBMLanguage_CBM_LANG_C);
    /// C++ grammar. Shares libcbm's `parse_c_imports` preprocessor-include path
    /// with [`Self::C`] and [`Self::OBJC`], so callers that reason about quote
    /// includes must treat all three as one family.
    pub const CPP: Self = Self(cbm_sys::CBMLanguage_CBM_LANG_CPP);
    /// Objective-C grammar. See [`Self::CPP`] for the shared include family.
    pub const OBJC: Self = Self(cbm_sys::CBMLanguage_CBM_LANG_OBJC);
    pub const RUST: Self = Self(cbm_sys::CBMLanguage_CBM_LANG_RUST);

    pub fn from_raw(raw: cbm_sys::CBMLanguage) -> Self {
        Self(raw)
    }

    pub fn as_raw(self) -> cbm_sys::CBMLanguage {
        self.0
    }

    /// Resolve the tree-sitter language for a file name/relative path exactly as
    /// the indexing pipeline does (`cbm_language_for_filename`), so a per-snippet
    /// reparse tags the snippet with the same grammar the symbol was indexed
    /// under. Returns `None` when libcbm has no grammar for the name
    /// (`CBM_LANG_COUNT` sentinel) — the caller must fail closed, never guess.
    pub fn from_filename(filename: &str) -> Option<Self> {
        let c = CString::new(filename).ok()?;
        // SAFETY: `c` is a valid NUL-terminated C string that outlives the call;
        // cbm_language_for_filename only reads it and returns a plain enum value.
        let raw = unsafe { cbm_sys::cbm_language_for_filename(c.as_ptr()) };
        if raw == cbm_sys::CBMLanguage_CBM_LANG_COUNT {
            None
        } else {
            Some(Self(raw))
        }
    }
}

pub fn map_cbm_status(status: i32) -> Result<(), BridgeError> {
    match status {
        0 => Ok(()),
        cbm_sys::CBM_PIPELINE_EMPTY_SOURCE_CORPUS => Err(envelope(
            "ASTRO_CBM_PIPELINE_EMPTY_SOURCE_CORPUS",
            "CBM refused to index a repository with zero non-auxiliary source files",
            "Add at least one supported readable source file or correct discovery, mode, and \
             ignore configuration before retrying.",
        )),
        -1 => Err(envelope(
            "ASTRO_CBM_STATUS_ERR",
            "CBM returned CBM_STORE_ERR",
            "Inspect the store path, input arguments, and CBM diagnostic output.",
        )),
        -2 => Err(envelope(
            "ASTRO_CBM_NOT_FOUND",
            "CBM returned CBM_STORE_NOT_FOUND",
            "Verify that the requested project, node, edge, or artifact exists.",
        )),
        other => Err(BridgeError::new(
            ErrorEnvelope::new(
                "ASTRO_CBM_INTERNAL",
                format!("CBM returned unknown status code {other}"),
                "Treat this as an FFI contract drift until the code is documented and mapped.",
            )
            .with_stderr(format!("unknown CBM status code: {other}")),
        )),
    }
}

pub const CALLBACK_OK: i32 = 0;
pub const CALLBACK_ERROR: i32 = -1;
pub const CALLBACK_PANIC: i32 = -2;

pub fn catch_unwind_to_envelope<F, T>(f: F) -> Result<T, BridgeError>
where
    F: FnOnce() -> T + std::panic::UnwindSafe,
{
    std::panic::catch_unwind(f).map_err(|_| {
        envelope(
            "ASTRO_FFI_CALLBACK_PANIC",
            "Rust callback panicked before returning to C",
            "Keep panic boundaries inside Rust; convert callback failures into status codes.",
        )
    })
}

pub fn guard_ffi_callback<F>(f: F) -> i32
where
    F: FnOnce() -> Result<(), BridgeError> + std::panic::UnwindSafe,
{
    match std::panic::catch_unwind(f) {
        Ok(Ok(())) => CALLBACK_OK,
        Ok(Err(_)) => CALLBACK_ERROR,
        Err(_) => CALLBACK_PANIC,
    }
}

/// Runs a CBM row-sink node callback behind the Rust FFI panic/error boundary.
///
/// # Safety
///
/// `node` must either be NULL or point to a CBM-owned `cbm_gbuf_row_node_t`
/// that remains valid for the duration of this call.
pub unsafe fn guard_row_sink_node_callback<F>(
    node: *const cbm_sys::cbm_gbuf_row_node_t,
    f: F,
) -> i32
where
    F: FnOnce(&cbm_sys::cbm_gbuf_row_node_t) -> Result<(), BridgeError> + std::panic::UnwindSafe,
{
    guard_ffi_callback(|| {
        let node = unsafe { node.as_ref() }.ok_or_else(|| {
            envelope(
                "ASTRO_CBM_ROW_SINK_NULL_NODE",
                "CBM row-sink node callback received NULL",
                "Treat this as FFI contract drift; callbacks require a borrowed row pointer.",
            )
        })?;
        f(node)
    })
}

/// Runs a CBM row-sink edge callback behind the Rust FFI panic/error boundary.
///
/// # Safety
///
/// `edge` must either be NULL or point to a CBM-owned `cbm_gbuf_row_edge_t`
/// that remains valid for the duration of this call.
pub unsafe fn guard_row_sink_edge_callback<F>(
    edge: *const cbm_sys::cbm_gbuf_row_edge_t,
    f: F,
) -> i32
where
    F: FnOnce(&cbm_sys::cbm_gbuf_row_edge_t) -> Result<(), BridgeError> + std::panic::UnwindSafe,
{
    guard_ffi_callback(|| {
        let edge = unsafe { edge.as_ref() }.ok_or_else(|| {
            envelope(
                "ASTRO_CBM_ROW_SINK_NULL_EDGE",
                "CBM row-sink edge callback received NULL",
                "Treat this as FFI contract drift; callbacks require a borrowed row pointer.",
            )
        })?;
        f(edge)
    })
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CbmIndexMode {
    Full,
    Moderate,
    Fast,
}

impl CbmIndexMode {
    fn as_raw(self) -> cbm_sys::cbm_index_mode_t {
        match self {
            Self::Full => cbm_sys::cbm_index_mode_t_CBM_MODE_FULL,
            Self::Moderate => cbm_sys::cbm_index_mode_t_CBM_MODE_MODERATE,
            Self::Fast => cbm_sys::cbm_index_mode_t_CBM_MODE_FAST,
        }
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Full => "full",
            Self::Moderate => "moderate",
            Self::Fast => "fast",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum CbmSemanticState {
    Available,
    UnavailableMode,
    UnavailableCorpus,
}

impl CbmSemanticState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Available => "available",
            Self::UnavailableMode => "unavailable_mode",
            Self::UnavailableCorpus => "unavailable_corpus",
        }
    }
}

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct CbmIndexCapability {
    pub index_mode: CbmIndexMode,
    pub semantic_state: CbmSemanticState,
    pub vector_dimension: usize,
    pub eligible_node_count: Option<usize>,
    pub node_vector_count: usize,
    pub token_vector_count: usize,
}

impl CbmIndexCapability {
    pub const VECTOR_DIMENSION: usize = 768;
    pub const MIN_ELIGIBLE_NODES: usize = 2;
    const ELIGIBLE_NOT_EVALUATED: i32 = -1;

    pub fn is_valid(self) -> bool {
        if self.vector_dimension != Self::VECTOR_DIMENSION {
            return false;
        }
        match self.semantic_state {
            CbmSemanticState::Available => {
                self.index_mode != CbmIndexMode::Fast
                    && self
                        .eligible_node_count
                        .is_some_and(|count| count >= Self::MIN_ELIGIBLE_NODES)
                    && self.eligible_node_count == Some(self.node_vector_count)
                    && self.token_vector_count > 0
            }
            CbmSemanticState::UnavailableMode => {
                self.index_mode == CbmIndexMode::Fast
                    && self.eligible_node_count.is_none()
                    && self.node_vector_count == 0
                    && self.token_vector_count == 0
            }
            CbmSemanticState::UnavailableCorpus => {
                self.index_mode != CbmIndexMode::Fast
                    && self
                        .eligible_node_count
                        .is_some_and(|count| count < Self::MIN_ELIGIBLE_NODES)
                    && self.node_vector_count == 0
                    && self.token_vector_count == 0
            }
        }
    }
}

/// Exact result of libcbm discovery over a real filesystem tree.
///
/// Both counts come from the same `cbm_discover` implementation the pipeline
/// invokes, including mode filters, ignore policy, filename/language detection,
/// and auxiliary-input classification. Callers can therefore avoid starting an
/// extraction for a deliberately empty source view without duplicating that
/// policy in Rust.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct CbmDiscoverySummary {
    pub discovered_files: usize,
    pub source_files: usize,
}

/// Run libcbm's authoritative discovery phase against `repo_path`.
pub fn discover_pipeline_files(
    repo_path: &str,
    mode: CbmIndexMode,
) -> Result<CbmDiscoverySummary, BridgeError> {
    initialize_cbm_allocator()?;
    let repo_path = CString::new(repo_path)?;
    let options = cbm_sys::cbm_discover_opts_t {
        mode: mode.as_raw(),
        ignore_file: ptr::null(),
        max_file_size: 0,
    };
    let mut files = ptr::null_mut();
    let mut count = 0;
    // SAFETY: every pointer references live storage for the duration of the call.
    // On success libcbm owns the returned array until `cbm_discover_free` below.
    let status =
        unsafe { cbm_sys::cbm_discover(repo_path.as_ptr(), &options, &mut files, &mut count) };
    if status != 0 {
        if !files.is_null() {
            // SAFETY: a non-null partial result is still libcbm-owned and uses the
            // non-negative portion of the count published by the same call.
            unsafe { cbm_sys::cbm_discover_free(files, count.max(0)) };
        }
        return Err(envelope(
            "ASTRO_CBM_DISCOVERY_FAILED",
            format!("libcbm discovery failed with status {status} for {repo_path:?}"),
            "Inspect the discovery diagnostic for the exact path, ignore-policy, or filesystem failure and retry only after correcting it.",
        ));
    }
    if count < 0 {
        if !files.is_null() {
            // SAFETY: an invalid negative count cannot describe initialized rows;
            // zero releases the outer allocation without indexing through it.
            unsafe { cbm_sys::cbm_discover_free(files, 0) };
        }
        return Err(envelope(
            "ASTRO_CBM_DISCOVERY_COUNT_INVALID",
            format!("libcbm discovery returned an invalid file count {count}"),
            "Treat this as FFI contract drift; repair the discovery count before indexing.",
        ));
    }
    let discovered_files = count as usize;
    if discovered_files > 0 && files.is_null() {
        return Err(envelope(
            "ASTRO_CBM_DISCOVERY_ROWS_MISSING",
            format!("libcbm reported {discovered_files} discovered files with a null row array"),
            "Treat this as FFI contract drift; repair the discovery ownership contract before indexing.",
        ));
    }
    let source_files = if discovered_files == 0 {
        0
    } else {
        // SAFETY: successful discovery returned a non-null array containing exactly
        // `discovered_files` initialized rows, retained until the free below.
        unsafe { std::slice::from_raw_parts(files, discovered_files) }
            .iter()
            .filter(|file| !file.auxiliary)
            .count()
    };
    if !files.is_null() {
        // SAFETY: the pointer/count pair is the exact successful discovery result and
        // is consumed once here.
        unsafe { cbm_sys::cbm_discover_free(files, count) };
    }
    Ok(CbmDiscoverySummary {
        discovered_files,
        source_files,
    })
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CbmPipelineNodeRow {
    pub id: i64,
    pub project: String,
    pub label: String,
    pub name: String,
    pub atom_id: String,
    pub qualified_name: String,
    pub file_path: String,
    pub start_line: i64,
    pub end_line: i64,
    pub source_present: bool,
    pub source_bytes: Vec<u8>,
    pub source_sha256: String,
    pub start_byte: u64,
    pub end_byte: u64,
    pub properties_json: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CbmPipelineEdgeRow {
    pub id: i64,
    pub project: String,
    pub source_id: i64,
    pub target_id: i64,
    pub edge_type: String,
    pub properties_json: String,
    pub url_path_gen: String,
    pub local_name_gen: String,
    pub preprocess_context_id_gen: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CbmPipelineFileHashRow {
    pub project: String,
    pub rel_path: String,
    pub sha256: String,
    pub mtime_ns: i64,
    pub size: i64,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CbmPipelineRowManifest {
    pub project: String,
    pub node_count: usize,
    pub edge_count: usize,
    pub file_hash_count: usize,
    pub graph_schema_version: u32,
    pub index_capability: CbmIndexCapability,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CbmPipelineRows {
    pub project: String,
    pub nodes: Vec<CbmPipelineNodeRow>,
    pub edges: Vec<CbmPipelineEdgeRow>,
    pub file_hashes: Vec<CbmPipelineFileHashRow>,
    pub manifest: Option<CbmPipelineRowManifest>,
}

pub fn pipeline_rows_success_response_value(rows: &CbmPipelineRows) -> serde_json::Value {
    serde_json::json!({
        "ok": true,
        "project": rows.project,
        "nodes": rows.nodes.iter().map(|n| serde_json::json!({
            "id": n.id,
            "project": n.project,
            "label": n.label,
            "name": n.name,
            "atom_id": n.atom_id,
            "qualified_name": n.qualified_name,
            "file_path": n.file_path,
            "start_line": n.start_line,
            "end_line": n.end_line,
            "source_present": n.source_present,
            "source_bytes": n.source_bytes,
            "source_sha256": n.source_sha256,
            "start_byte": n.start_byte,
            "end_byte": n.end_byte,
            "properties_json": n.properties_json,
        })).collect::<Vec<_>>(),
        "edges": rows.edges.iter().map(|e| serde_json::json!({
            "id": e.id,
            "project": e.project,
            "source_id": e.source_id,
            "target_id": e.target_id,
            "edge_type": e.edge_type,
            "properties_json": e.properties_json,
            "url_path_gen": e.url_path_gen,
            "local_name_gen": e.local_name_gen,
            "preprocess_context_id_gen": e.preprocess_context_id_gen,
        })).collect::<Vec<_>>(),
        "file_hashes": rows.file_hashes.iter().map(|f| serde_json::json!({
            "project": f.project,
            "rel_path": f.rel_path,
            "sha256": f.sha256,
            "mtime_ns": f.mtime_ns,
            "size": f.size,
        })).collect::<Vec<_>>(),
        "manifest": rows.manifest.as_ref().map(|m| serde_json::json!({
            "project": m.project,
            "node_count": m.node_count,
            "edge_count": m.edge_count,
            "file_hash_count": m.file_hash_count,
            "graph_schema_version": m.graph_schema_version,
            "index_mode": m.index_capability.index_mode.as_str(),
            "semantic_state": m.index_capability.semantic_state.as_str(),
            "semantic_vector_dimension": m.index_capability.vector_dimension,
            "semantic_eligible_node_count": m.index_capability.eligible_node_count,
            "node_vector_count": m.index_capability.node_vector_count,
            "token_vector_count": m.index_capability.token_vector_count,
        })),
    })
}

/// Result of a single `index_repository` run with the pipeline row sink attached.
///
/// The raw tool result and the row capture succeed or fail independently (#123):
/// by the time the sink outcome is known the index has already completed, so a
/// sink failure must not discard `raw_json` and force the caller into a full
/// second index run. `rows` carries the sink failure instead.
#[derive(Debug)]
pub struct CbmIndexRepositoryRows {
    /// Raw JSON tool result of the completed `index_repository` run.
    pub raw_json: String,
    /// Captured pipeline rows, or the row-sink failure for this same run.
    pub rows: Result<CbmPipelineRows, BridgeError>,
}

struct PipelineRowSinkState {
    owner: ThreadId,
    nodes: Vec<CbmPipelineNodeRow>,
    edges: Vec<CbmPipelineEdgeRow>,
    file_hashes: Vec<CbmPipelineFileHashRow>,
    manifest: Option<CbmPipelineRowManifest>,
    error: Option<BridgeError>,
    success_publisher: Option<PipelineSuccessPublisher>,
}

struct PipelineSuccessPublisher {
    response_tmp: PathBuf,
    response_path: PathBuf,
    published: bool,
}

impl PipelineRowSinkState {
    fn new() -> Self {
        Self {
            owner: thread::current().id(),
            nodes: Vec::new(),
            edges: Vec::new(),
            file_hashes: Vec::new(),
            manifest: None,
            error: None,
            success_publisher: None,
        }
    }

    fn new_with_success_publisher(response_tmp: PathBuf, response_path: PathBuf) -> Self {
        let mut state = Self::new();
        state.success_publisher = Some(PipelineSuccessPublisher {
            response_tmp,
            response_path,
            published: false,
        });
        state
    }

    fn ensure_callback_thread(&self) -> Result<(), BridgeError> {
        if thread::current().id() == self.owner {
            return Ok(());
        }
        Err(envelope(
            "ASTRO_CBM_ROW_SINK_THREAD",
            "CBM row-sink callback arrived on a different thread than the owning pipeline runner",
            "Keep row-sink callbacks on the thread that installed the sink, or use an explicitly synchronized sink state.",
        ))
    }

    fn push_node(&mut self, row: &cbm_sys::cbm_gbuf_row_node_t) -> Result<(), BridgeError> {
        self.ensure_callback_thread()?;
        if row.source_present != 0 && row.source_present != 1 {
            return Err(envelope(
                "ASTRO_CBM_ROW_SOURCE_FLAG",
                format!(
                    "CBM row-sink node {} has invalid source_present {}",
                    row.id, row.source_present
                ),
                "Fix libcbm to emit source_present as exactly zero or one.",
            ));
        }
        let source_present = row.source_present == 1;
        if row.source_len > 0 && row.source_bytes.is_null() {
            return Err(envelope(
                "ASTRO_CBM_ROW_SOURCE_POINTER",
                format!(
                    "CBM row-sink node {} has {} source bytes but a null pointer",
                    row.id, row.source_len
                ),
                "Preserve the source allocation through the complete callback duration.",
            ));
        }
        let source_bytes = if row.source_len == 0 {
            Vec::new()
        } else {
            // SAFETY: the row-sink ABI guarantees this borrowed allocation remains
            // live for the callback; the null/length relation was checked above.
            unsafe { std::slice::from_raw_parts(row.source_bytes, row.source_len) }.to_vec()
        };
        self.nodes.push(CbmPipelineNodeRow {
            id: row.id,
            project: required_borrowed_c_string(row.project, "row_sink.node.project")?,
            label: required_borrowed_c_string(row.label, "row_sink.node.label")?,
            name: required_borrowed_c_string(row.name, "row_sink.node.name")?,
            atom_id: required_borrowed_c_string(row.atom_id, "row_sink.node.atom_id")?,
            qualified_name: required_borrowed_c_string(
                row.qualified_name,
                "row_sink.node.qualified_name",
            )?,
            file_path: required_borrowed_c_string(row.file_path, "row_sink.node.file_path")?,
            start_line: i64::from(row.start_line),
            end_line: i64::from(row.end_line),
            source_present,
            source_bytes,
            source_sha256: required_borrowed_c_string(
                row.source_sha256,
                "row_sink.node.source_sha256",
            )?,
            start_byte: row.start_byte,
            end_byte: row.end_byte,
            properties_json: required_borrowed_c_string(
                row.properties_json,
                "row_sink.node.properties_json",
            )?,
        });
        Ok(())
    }

    fn push_edge(&mut self, row: &cbm_sys::cbm_gbuf_row_edge_t) -> Result<(), BridgeError> {
        self.ensure_callback_thread()?;
        let properties_json =
            required_borrowed_c_string(row.properties_json, "row_sink.edge.properties_json")?;
        let properties: serde_json::Value =
            serde_json::from_str(&properties_json).map_err(|error| {
                envelope(
                    "ASTRO_CBM_ROW_SINK_EDGE_PROPERTIES_INVALID",
                    format!(
                        "row-sink edge {} properties are not valid JSON: {error}",
                        row.id
                    ),
                    "Preserve the source corpus and repair CBM edge-property serialization.",
                )
            })?;
        if !properties.is_object() {
            return Err(envelope(
                "ASTRO_CBM_ROW_SINK_EDGE_PROPERTIES_INVALID",
                format!("row-sink edge {} properties are not a JSON object", row.id),
                "Preserve the source corpus and repair CBM edge-property serialization.",
            ));
        }
        let preprocess_context_id_gen = match properties.get("preprocess_context_id") {
            None | Some(serde_json::Value::Null) => String::new(),
            Some(serde_json::Value::String(value)) => value.clone(),
            Some(value) => {
                return Err(envelope(
                    "ASTRO_CBM_ROW_SINK_EDGE_IDENTITY_INVALID",
                    format!(
                        "row-sink edge {} preprocess_context_id must be text or null, observed {value}",
                        row.id
                    ),
                    "Repair the exact preprocessing-context identity and run a clean re-index.",
                ));
            }
        };
        self.edges.push(CbmPipelineEdgeRow {
            id: row.id,
            project: required_borrowed_c_string(row.project, "row_sink.edge.project")?,
            source_id: row.source_id,
            target_id: row.target_id,
            edge_type: required_borrowed_c_string(row.type_, "row_sink.edge.type")?,
            properties_json,
            url_path_gen: required_borrowed_c_string(
                row.url_path_gen,
                "row_sink.edge.url_path_gen",
            )?,
            local_name_gen: required_borrowed_c_string(
                row.local_name_gen,
                "row_sink.edge.local_name_gen",
            )?,
            preprocess_context_id_gen,
        });
        Ok(())
    }

    fn push_file_hash(
        &mut self,
        row: &cbm_sys::cbm_pipeline_row_file_hash_t,
    ) -> Result<(), BridgeError> {
        self.ensure_callback_thread()?;
        let project = required_borrowed_c_string(row.project, "row_sink.file_hash.project")?;
        let rel_path = required_borrowed_c_string(row.rel_path, "row_sink.file_hash.rel_path")?;
        let sha256 = required_borrowed_c_string(row.sha256, "row_sink.file_hash.sha256")?;
        if rel_path.is_empty() || rel_path.contains('\\') {
            return Err(envelope(
                "ASTRO_CBM_ROW_SINK_FILE_PATH",
                format!("CBM row-sink file hash has a noncanonical path {rel_path:?}"),
                "Emit one non-empty, forward-slash-normalized repository-relative path.",
            ));
        }
        if sha256.len() != 64
            || !sha256
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err(envelope(
                "ASTRO_CBM_ROW_SINK_FILE_DIGEST",
                format!("CBM row-sink file hash for {rel_path:?} is not lowercase SHA-256"),
                "Publish the exact 64-character lowercase SHA-256 captured from source bytes.",
            ));
        }
        if row.size < 0 {
            return Err(envelope(
                "ASTRO_CBM_ROW_SINK_FILE_STAT",
                format!(
                    "CBM row-sink file hash for {rel_path:?} has negative size {}",
                    row.size
                ),
                "Publish the non-negative size stored in the source SQLite row; modification time remains a signed Unix timestamp.",
            ));
        }
        self.file_hashes.push(CbmPipelineFileHashRow {
            project,
            rel_path,
            sha256,
            mtime_ns: row.mtime_ns,
            size: row.size,
        });
        Ok(())
    }

    fn complete(&mut self, row: &cbm_sys::cbm_pipeline_row_manifest_t) -> Result<(), BridgeError> {
        self.ensure_callback_thread()?;
        if self.manifest.is_some() {
            return Err(envelope(
                "ASTRO_CBM_ROW_SINK_MANIFEST_DUPLICATE",
                "CBM row-sink emitted more than one completion manifest",
                "Emit exactly one completion manifest after every snapshot row.",
            ));
        }
        let project = required_borrowed_c_string(row.project, "row_sink.manifest.project")?;
        let expected_schema = cbm_sys::CBM_GRAPH_SCHEMA_VERSION as u32;
        if row.graph_schema_version != expected_schema {
            return Err(envelope(
                "ASTRO_CBM_ROW_SINK_SCHEMA",
                format!(
                    "CBM row-sink manifest schema {} does not match supported schema {expected_schema}",
                    row.graph_schema_version
                ),
                "Rebuild both sides from the same graph-schema contract; no version fallback is supported.",
            ));
        }
        if row.node_count != self.nodes.len()
            || row.edge_count != self.edges.len()
            || row.file_hash_count != self.file_hashes.len()
        {
            return Err(envelope(
                "ASTRO_CBM_ROW_SINK_COUNT_MISMATCH",
                format!(
                    "CBM row-sink manifest declared nodes={}, edges={}, file_hashes={} but callbacks delivered nodes={}, edges={}, file_hashes={}",
                    row.node_count,
                    row.edge_count,
                    row.file_hash_count,
                    self.nodes.len(),
                    self.edges.len(),
                    self.file_hashes.len()
                ),
                "Repair the producer so every committed source row is emitted exactly once before completion.",
            ));
        }
        let raw_capability = row.index_capability;
        let index_mode = match raw_capability.index_mode {
            cbm_sys::cbm_index_mode_t_CBM_MODE_FULL => CbmIndexMode::Full,
            cbm_sys::cbm_index_mode_t_CBM_MODE_MODERATE => CbmIndexMode::Moderate,
            cbm_sys::cbm_index_mode_t_CBM_MODE_FAST => CbmIndexMode::Fast,
            other => {
                return Err(envelope(
                    "ASTRO_CBM_ROW_SINK_CAPABILITY_INVALID",
                    format!("CBM row-sink manifest carried unsupported index mode {other}"),
                    "Rebuild both sides from the exact schema-v6 capability contract.",
                ));
            }
        };
        let semantic_state = match raw_capability.semantic_state {
            cbm_sys::cbm_semantic_state_t_CBM_SEMANTIC_AVAILABLE => CbmSemanticState::Available,
            cbm_sys::cbm_semantic_state_t_CBM_SEMANTIC_UNAVAILABLE_MODE => {
                CbmSemanticState::UnavailableMode
            }
            cbm_sys::cbm_semantic_state_t_CBM_SEMANTIC_UNAVAILABLE_CORPUS => {
                CbmSemanticState::UnavailableCorpus
            }
            other => {
                return Err(envelope(
                    "ASTRO_CBM_ROW_SINK_CAPABILITY_INVALID",
                    format!("CBM row-sink manifest carried unsupported semantic state {other}"),
                    "Rebuild both sides from the exact schema-v6 capability contract.",
                ));
            }
        };
        let vector_dimension = usize::try_from(raw_capability.vector_dimension).map_err(|_| {
            envelope(
                "ASTRO_CBM_ROW_SINK_CAPABILITY_INVALID",
                "CBM row-sink manifest carried a negative semantic vector dimension",
                "Repair the native capability producer; no inferred dimension is accepted.",
            )
        })?;
        let node_vector_count =
            usize::try_from(raw_capability.node_vector_count).map_err(|_| {
                envelope(
                    "ASTRO_CBM_ROW_SINK_CAPABILITY_INVALID",
                    "CBM row-sink manifest carried a negative node-vector count",
                    "Repair the native capability producer; no inferred count is accepted.",
                )
            })?;
        let token_vector_count =
            usize::try_from(raw_capability.token_vector_count).map_err(|_| {
                envelope(
                    "ASTRO_CBM_ROW_SINK_CAPABILITY_INVALID",
                    "CBM row-sink manifest carried a negative token-vector count",
                    "Repair the native capability producer; no inferred count is accepted.",
                )
            })?;
        let eligible_node_count = match raw_capability.eligible_node_count {
            CbmIndexCapability::ELIGIBLE_NOT_EVALUATED => None,
            value => Some(usize::try_from(value).map_err(|_| {
                envelope(
                    "ASTRO_CBM_ROW_SINK_CAPABILITY_INVALID",
                    "CBM row-sink manifest carried an invalid eligible-node count",
                    "Repair the native capability producer; no inferred count is accepted.",
                )
            })?),
        };
        let index_capability = CbmIndexCapability {
            index_mode,
            semantic_state,
            vector_dimension,
            eligible_node_count,
            node_vector_count,
            token_vector_count,
        };
        if !index_capability.is_valid() {
            return Err(envelope(
                "ASTRO_CBM_ROW_SINK_CAPABILITY_INVALID",
                format!(
                    "CBM row-sink manifest carried an inconsistent capability {index_capability:?}"
                ),
                "Repair the native semantic producer and publish one exact capability generation.",
            ));
        }
        if self.nodes.iter().any(|node| node.project != project)
            || self.edges.iter().any(|edge| edge.project != project)
            || self
                .file_hashes
                .iter()
                .any(|file_hash| file_hash.project != project)
        {
            return Err(envelope(
                "ASTRO_CBM_ROW_SINK_PROJECT_MISMATCH",
                format!("CBM row-sink rows do not all belong to manifest project {project:?}"),
                "Publish one project-scoped snapshot per completed sink invocation.",
            ));
        }
        let mut paths = self
            .file_hashes
            .iter()
            .map(|file_hash| file_hash.rel_path.as_str())
            .collect::<Vec<_>>();
        paths.sort_unstable();
        if paths.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(envelope(
                "ASTRO_CBM_ROW_SINK_FILE_DUPLICATE",
                "CBM row-sink emitted duplicate file-hash paths",
                "Publish exactly one final file-hash row per repository-relative path.",
            ));
        }
        self.manifest = Some(CbmPipelineRowManifest {
            project,
            node_count: row.node_count,
            edge_count: row.edge_count,
            file_hash_count: row.file_hash_count,
            graph_schema_version: row.graph_schema_version,
            index_capability,
        });
        Ok(())
    }

    fn completed_rows(&self) -> Result<CbmPipelineRows, BridgeError> {
        let manifest = self.manifest.as_ref().ok_or_else(|| {
            envelope(
                "ASTRO_CBM_ROW_SINK_INCOMPLETE",
                "CBM post-success callback fired before the row-sink completion manifest",
                "Repair the native pipeline ordering: post-success requires a completed row snapshot.",
            )
        })?;
        Ok(CbmPipelineRows {
            project: manifest.project.clone(),
            nodes: self.nodes.clone(),
            edges: self.edges.clone(),
            file_hashes: self.file_hashes.clone(),
            manifest: Some(manifest.clone()),
        })
    }

    fn publish_success_response(&mut self) -> Result<(), BridgeError> {
        self.ensure_callback_thread()?;
        let rows = self.completed_rows()?;
        let Some(publisher) = self.success_publisher.as_mut() else {
            return Ok(());
        };
        if publisher.published {
            return Err(envelope(
                "ASTRO_CBM_ROW_SINK_SUCCESS_RESPONSE_DUPLICATE",
                "CBM post-success callback tried to publish the same row snapshot twice",
                "Emit exactly one post-success callback per successful pipeline run.",
            ));
        }
        if publisher.response_path.exists() {
            return Err(envelope(
                "ASTRO_CBM_ROW_SINK_SUCCESS_RESPONSE_COLLISION",
                format!(
                    "success response path {} already exists before publication",
                    publisher.response_path.display()
                ),
                "Preserve the colliding response file; a fresh worker sequence must start from an absent response path.",
            ));
        }
        let bytes =
            serde_json::to_vec(&pipeline_rows_success_response_value(&rows)).map_err(|error| {
                envelope(
                    "ASTRO_CBM_ROW_SINK_SUCCESS_RESPONSE_SERIALIZE",
                    format!("could not serialize the completed row snapshot: {error}"),
                    "Inspect the row values and repair the response serializer before retrying.",
                )
            })?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&publisher.response_tmp)
            .map_err(|error| {
                envelope(
                    "ASTRO_CBM_ROW_SINK_SUCCESS_RESPONSE_TEMP_OPEN",
                    format!(
                        "could not create success response temp file {}: {error}",
                        publisher.response_tmp.display()
                    ),
                    "Ensure the archaeology pool directory is writable and contains no stale temp response.",
                )
            })?;
        file.write_all(&bytes).map_err(|error| {
            envelope(
                "ASTRO_CBM_ROW_SINK_SUCCESS_RESPONSE_TEMP_WRITE",
                format!(
                    "could not write complete success response temp file {}: {error}",
                    publisher.response_tmp.display()
                ),
                "Inspect the storage device and retry with the preserved temp file absent.",
            )
        })?;
        file.sync_all().map_err(|error| {
            envelope(
                "ASTRO_CBM_ROW_SINK_SUCCESS_RESPONSE_TEMP_SYNC",
                format!(
                    "could not flush success response temp file {}: {error}",
                    publisher.response_tmp.display()
                ),
                "Inspect the storage device before trusting worker response publication.",
            )
        })?;
        drop(file);
        fs::rename(&publisher.response_tmp, &publisher.response_path).map_err(|error| {
            envelope(
                "ASTRO_CBM_ROW_SINK_SUCCESS_RESPONSE_RENAME",
                format!(
                    "could not atomically publish success response {} -> {}: {error}",
                    publisher.response_tmp.display(),
                    publisher.response_path.display()
                ),
                "Preserve both paths and retry only after the response namespace is absent.",
            )
        })?;
        publisher.published = true;
        Ok(())
    }

    fn finish_callback(&mut self, result: std::thread::Result<Result<(), BridgeError>>) -> c_int {
        match result {
            Ok(Ok(())) => CALLBACK_OK,
            Ok(Err(error)) => {
                self.remember_error(error);
                CALLBACK_ERROR
            }
            Err(_) => {
                self.remember_error(envelope(
                    "ASTRO_FFI_CALLBACK_PANIC",
                    "Rust row-sink callback panicked before returning to C",
                    "Keep panic boundaries inside Rust; convert callback failures into status codes.",
                ));
                CALLBACK_PANIC
            }
        }
    }

    fn remember_error(&mut self, error: BridgeError) {
        if self.error.is_none() {
            self.error = Some(error);
        }
    }
}

#[derive(Debug)]
struct RepositoryCompileCommand {
    file: String,
    language: &'static str,
    directory: String,
    arguments: Vec<String>,
    preprocess_arguments: Vec<String>,
    dependencies: Vec<String>,
    baseline_index: usize,
}

#[derive(Debug)]
struct RepositoryCompilerBaseline {
    predefined_macros: Vec<String>,
    system_include_paths: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct RepositorySourceDateEpoch {
    value: String,
    revision: String,
    repository_root: String,
}

fn repository_source_date_epoch_with_root(
    repo_root: &Path,
    known_repository_root: Option<&Path>,
) -> Result<RepositorySourceDateEpoch, BridgeError> {
    let repository_path = if let Some(repository_root) = known_repository_root {
        canonical_path(
            repository_root,
            "ASTRO_COMPILE_CONTEXT_SOURCE_EPOCH_REPOSITORY_UNRESOLVED",
            "known Git repository root",
        )?
    } else if repo_root.join(".git").exists() {
        repo_root.to_path_buf()
    } else {
        let repository_output = Command::new("git")
            .args(["-C"])
            .arg(repo_root)
            .args(["rev-parse", "--show-toplevel"])
            .stdin(Stdio::null())
            .output()
            .map_err(|error| {
                envelope(
                    "ASTRO_COMPILE_CONTEXT_SOURCE_EPOCH_UNREACHABLE",
                    format!(
                        "cannot execute git while deriving SOURCE_DATE_EPOCH for {}: {error}",
                        repo_root.display()
                    ),
                    "Restore Git on PATH and retry the unchanged Git repository.",
                )
            })?;
        if !repository_output.status.success() {
            return Err(BridgeError::new(
                ErrorEnvelope::new(
                    "ASTRO_COMPILE_CONTEXT_SOURCE_EPOCH_REPOSITORY_REQUIRED",
                    format!(
                        "{} is not inside a Git repository with a readable work-tree root",
                        repo_root.display()
                    ),
                    "Index a committed Git repository or remove its compilation database until an exact source epoch can be supplied.",
                )
                .with_stderr(String::from_utf8_lossy(&repository_output.stderr)),
            ));
        }
        let repository_text = std::str::from_utf8(&repository_output.stdout).map_err(|error| {
            envelope(
                "ASTRO_COMPILE_CONTEXT_SOURCE_EPOCH_REPOSITORY_INVALID",
                format!("Git repository-root output is not UTF-8: {error}"),
                "Repair the repository path encoding and retry the unchanged repository.",
            )
        })?;
        let repository_text = repository_text.trim_end_matches(['\r', '\n']);
        if repository_text.is_empty()
            || repository_text.contains('\r')
            || repository_text.contains('\n')
        {
            return Err(envelope(
                "ASTRO_COMPILE_CONTEXT_SOURCE_EPOCH_REPOSITORY_INVALID",
                "Git returned an empty or multi-line repository root",
                "Repair the Git work-tree metadata and retry the unchanged repository.",
            ));
        }
        canonical_path(
            Path::new(repository_text),
            "ASTRO_COMPILE_CONTEXT_SOURCE_EPOCH_REPOSITORY_UNRESOLVED",
            "Git repository root",
        )?
    };
    if !repo_root.starts_with(&repository_path) {
        return Err(envelope(
            "ASTRO_COMPILE_CONTEXT_SOURCE_EPOCH_REPOSITORY_MISMATCH",
            format!(
                "indexed root {} is not within Git root {}",
                repo_root.display(),
                repository_path.display()
            ),
            "Preserve both paths and repair the repository work-tree metadata.",
        ));
    }

    let epoch_output = Command::new("git")
        .args(["-C"])
        .arg(&repository_path)
        .args([
            "log",
            "-1",
            "--no-show-signature",
            "--format=%H%n%ct",
            "HEAD",
            "--",
        ])
        .stdin(Stdio::null())
        .output()
        .map_err(|error| {
            envelope(
                "ASTRO_COMPILE_CONTEXT_SOURCE_EPOCH_UNREACHABLE",
                format!(
                    "cannot execute git while reading HEAD epoch for {}: {error}",
                    repository_path.display()
                ),
                "Restore Git on PATH and retry the unchanged Git repository.",
            )
        })?;
    if !epoch_output.status.success() {
        return Err(BridgeError::new(
            ErrorEnvelope::new(
                "ASTRO_COMPILE_CONTEXT_SOURCE_EPOCH_COMMIT_REQUIRED",
                format!(
                    "Git repository {} has no readable HEAD commit epoch",
                    repository_path.display()
                ),
                "Commit the source generation and retry, or remove the compilation database until an exact source epoch exists.",
            )
            .with_stderr(String::from_utf8_lossy(&epoch_output.stderr)),
        ));
    }
    let epoch_text = std::str::from_utf8(&epoch_output.stdout).map_err(|error| {
        envelope(
            "ASTRO_COMPILE_CONTEXT_SOURCE_EPOCH_INVALID",
            format!("Git HEAD epoch output is not UTF-8: {error}"),
            "Repair the repository commit metadata and retry the unchanged repository.",
        )
    })?;
    let mut lines = epoch_text.lines();
    let revision = lines.next().unwrap_or_default();
    let value = lines.next().unwrap_or_default();
    if lines.next().is_some()
        || !matches!(revision.len(), 40 | 64)
        || !revision.bytes().all(|byte| byte.is_ascii_hexdigit())
        || value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
        || value.parse::<u64>().is_err()
    {
        return Err(envelope(
            "ASTRO_COMPILE_CONTEXT_SOURCE_EPOCH_INVALID",
            format!(
                "Git returned a non-canonical HEAD revision/epoch pair for {}",
                repository_path.display()
            ),
            "Repair the Git commit metadata so `%H` is hexadecimal and `%ct` is a canonical Unix timestamp.",
        ));
    }
    Ok(RepositorySourceDateEpoch {
        value: value.to_owned(),
        revision: revision.to_ascii_lowercase(),
        repository_root: normalized_path(&repository_path),
    })
}

fn repository_source_date_epoch(
    repo_root: &Path,
) -> Result<RepositorySourceDateEpoch, BridgeError> {
    repository_source_date_epoch_with_root(repo_root, None)
}

fn normalized_path(path: &Path) -> String {
    let text = path.to_string_lossy();
    if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
        format!("//{}", rest.replace('\\', "/"))
    } else if let Some(rest) = text.strip_prefix(r"\\?\") {
        rest.replace('\\', "/")
    } else {
        text.replace('\\', "/")
    }
}

fn canonical_path(path: &Path, code: &str, purpose: &str) -> Result<PathBuf, BridgeError> {
    path.canonicalize().map_err(|error| {
        envelope(
            code,
            format!("cannot resolve {purpose} at {}: {error}", path.display()),
            "Correct the recorded repository/build path and regenerate compile_commands.json.",
        )
    })
}

fn path_within_repo(repo_root: &Path, path: &Path) -> Option<String> {
    let canonical = path.canonicalize().ok()?;
    let relative = canonical.strip_prefix(repo_root).ok()?;
    Some(normalized_path(relative))
}

fn command_entry_arguments(
    entry: &serde_json::Value,
    file: &str,
) -> Result<Vec<String>, BridgeError> {
    if let Some(arguments) = entry.get("arguments") {
        let array = arguments.as_array().ok_or_else(|| {
            envelope(
                "ASTRO_COMPILE_CONTEXT_ARGUMENTS_INVALID",
                format!("compilation command for {file} has a non-array arguments field"),
                "Regenerate compile_commands.json with one exact string argv array per entry.",
            )
        })?;
        let mut argv = Vec::with_capacity(array.len());
        for argument in array {
            let argument = argument.as_str().ok_or_else(|| {
                envelope(
                    "ASTRO_COMPILE_CONTEXT_ARGUMENT_INVALID",
                    format!("compilation command for {file} contains a non-string argument"),
                    "Regenerate compile_commands.json without lossy or typed argv elements.",
                )
            })?;
            if argument.is_empty() {
                return Err(envelope(
                    "ASTRO_COMPILE_CONTEXT_ARGUMENT_EMPTY",
                    format!("compilation command for {file} contains an empty argv element"),
                    "Regenerate the compilation database from the real build invocation.",
                ));
            }
            argv.push(argument.to_owned());
        }
        if argv.is_empty() {
            return Err(envelope(
                "ASTRO_COMPILE_CONTEXT_ARGUMENTS_EMPTY",
                format!("compilation command for {file} has an empty argv"),
                "Regenerate compile_commands.json from the real build invocation.",
            ));
        }
        return Ok(argv);
    }

    let command = entry
        .get("command")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            envelope(
                "ASTRO_COMPILE_CONTEXT_COMMAND_MISSING",
                format!("compilation command for {file} has neither arguments nor command"),
                "Regenerate compile_commands.json with one complete command per translation unit.",
            )
        })?;
    split_native_command_line(command, file)
}

#[cfg(windows)]
fn split_native_command_line(command: &str, file: &str) -> Result<Vec<String>, BridgeError> {
    use std::ffi::OsStr;
    use std::os::windows::ffi::OsStrExt;

    #[link(name = "shell32")]
    unsafe extern "system" {
        fn CommandLineToArgvW(command_line: *const u16, argument_count: *mut i32) -> *mut *mut u16;
    }
    #[link(name = "kernel32")]
    unsafe extern "system" {
        fn LocalFree(memory: *mut c_void) -> *mut c_void;
    }

    let wide = OsStr::new(command)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<_>>();
    let mut count = 0i32;
    // SAFETY: `wide` is NUL-terminated and `count` is a writable out parameter.
    let raw = unsafe { CommandLineToArgvW(wide.as_ptr(), &mut count) };
    if raw.is_null() || count <= 0 {
        return Err(envelope(
            "ASTRO_COMPILE_CONTEXT_COMMAND_PARSE_FAILED",
            format!("native Windows argv parsing failed for compilation command {file}"),
            "Regenerate compile_commands.json with the arguments array form.",
        ));
    }
    let mut result = Vec::with_capacity(count as usize);
    for index in 0..count as usize {
        // SAFETY: CommandLineToArgvW returned an array containing `count` pointers,
        // each to a NUL-terminated UTF-16 argument owned by `raw`.
        let argument = unsafe {
            let pointer = *raw.add(index);
            let mut length = 0usize;
            while *pointer.add(length) != 0 {
                length += 1;
            }
            String::from_utf16(std::slice::from_raw_parts(pointer, length))
        };
        match argument {
            Ok(argument) if !argument.is_empty() => result.push(argument),
            Ok(_) => {
                // SAFETY: `raw` is the allocation returned by CommandLineToArgvW.
                unsafe { LocalFree(raw.cast()) };
                return Err(envelope(
                    "ASTRO_COMPILE_CONTEXT_ARGUMENT_EMPTY",
                    format!("native command parsing produced an empty argv element for {file}"),
                    "Regenerate compile_commands.json with the arguments array form.",
                ));
            }
            Err(error) => {
                // SAFETY: `raw` is the allocation returned by CommandLineToArgvW.
                unsafe { LocalFree(raw.cast()) };
                return Err(envelope(
                    "ASTRO_COMPILE_CONTEXT_COMMAND_UTF16_INVALID",
                    format!("native command parsing produced invalid UTF-16 for {file}: {error}"),
                    "Regenerate compile_commands.json with UTF-8 arguments.",
                ));
            }
        }
    }
    // SAFETY: `raw` is released once after every argument has been copied.
    unsafe { LocalFree(raw.cast()) };
    Ok(result)
}

#[cfg(not(windows))]
fn split_native_command_line(_command: &str, file: &str) -> Result<Vec<String>, BridgeError> {
    Err(envelope(
        "ASTRO_COMPILE_CONTEXT_COMMAND_PLATFORM_DEFERRED",
        format!("native command parsing is not implemented for {file} on this deferred platform"),
        "Use the compilation database arguments array form until the cross-platform phase.",
    ))
}

fn resolve_command_program(directory: &Path, program: &str) -> String {
    let path = Path::new(program);
    if path.is_absolute() || (!program.contains('/') && !program.contains('\\')) {
        return program.to_owned();
    }
    normalized_path(&directory.join(path))
}

fn option_consumes_value(argument: &str) -> bool {
    matches!(argument, "-o" | "-MF" | "-MT" | "-MQ" | "-MJ" | "-x")
}

fn is_dependency_or_output_option(argument: &str) -> bool {
    matches!(
        argument,
        "-c" | "-M" | "-MM" | "-MD" | "-MMD" | "-MP" | "-MG"
    ) || (argument.starts_with("-o") && argument.len() > 2)
        || (argument.starts_with("-MF") && argument.len() > 3)
        || (argument.starts_with("-MT") && argument.len() > 3)
        || (argument.starts_with("-MQ") && argument.len() > 3)
        || (argument.starts_with("-MJ") && argument.len() > 3)
}

fn argument_is_translation_unit(argument: &str, directory: &Path, file: &Path) -> bool {
    let candidate = Path::new(argument);
    let candidate = if candidate.is_absolute() {
        candidate.to_path_buf()
    } else {
        directory.join(candidate)
    };
    candidate
        .canonicalize()
        .is_ok_and(|candidate| candidate == file)
}

fn context_compiler_arguments(
    arguments: &[String],
    directory: &Path,
    file: &Path,
    keep_language: bool,
    keep_translation_unit: bool,
) -> Result<Vec<String>, BridgeError> {
    if arguments.is_empty() {
        return Err(envelope(
            "ASTRO_COMPILE_CONTEXT_ARGUMENTS_EMPTY",
            format!("translation unit {} has no compiler argv", file.display()),
            "Regenerate compile_commands.json from the real build.",
        ));
    }
    let mut result = vec![resolve_command_program(directory, &arguments[0])];
    let mut translation_unit_count = 0usize;
    let mut index = 1usize;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument.starts_with('@') {
            return Err(envelope(
                "ASTRO_COMPILE_CONTEXT_RESPONSE_FILE_OPAQUE",
                format!(
                    "translation unit {} uses opaque response file {argument}",
                    file.display()
                ),
                "Generate compile_commands.json with the response-file arguments expanded.",
            ));
        }
        if option_consumes_value(argument) {
            if index + 1 >= arguments.len() {
                return Err(envelope(
                    "ASTRO_COMPILE_CONTEXT_OPTION_VALUE_MISSING",
                    format!(
                        "translation unit {} ends after option {argument}",
                        file.display()
                    ),
                    "Regenerate the compilation database from a successful real build.",
                ));
            }
            if keep_language && argument == "-x" {
                result.push(argument.clone());
                result.push(arguments[index + 1].clone());
            }
            index += 2;
            continue;
        }
        if argument_is_translation_unit(argument, directory, file) {
            translation_unit_count = translation_unit_count.checked_add(1).ok_or_else(|| {
                envelope(
                    "ASTRO_COMPILE_CONTEXT_TU_ARGUMENT_OVERFLOW",
                    format!(
                        "translation-unit argument count overflows for {}",
                        file.display()
                    ),
                    "Regenerate compile_commands.json with one translation-unit argument per entry.",
                )
            })?;
            if keep_translation_unit {
                // The compile database is the command authority. Keep the exact
                // compiler-accepted spelling (including a relative path) rather
                // than reconstructing it from Windows canonical identity.
                result.push(argument.clone());
            }
        } else if !is_dependency_or_output_option(argument) {
            result.push(argument.clone());
        }
        index += 1;
    }
    if translation_unit_count != 1 {
        return Err(envelope(
            "ASTRO_COMPILE_CONTEXT_TU_ARGUMENT_CARDINALITY",
            format!(
                "translation unit {} has {translation_unit_count} matching argv elements; expected exactly one",
                file.display()
            ),
            "Regenerate compile_commands.json with exactly one compiler-accepted translation-unit argument per entry.",
        ));
    }
    Ok(result)
}

fn translation_unit_language(
    arguments: &[String],
    file: &Path,
) -> Result<&'static str, BridgeError> {
    let mut index = 0usize;
    while index < arguments.len() {
        if arguments[index] == "-x" && index + 1 < arguments.len() {
            return match arguments[index + 1].as_str() {
                "c" | "c-header" => Ok("c"),
                "c++" | "c++-header" | "cuda" => Ok("c++"),
                language => Err(envelope(
                    "ASTRO_COMPILE_CONTEXT_LANGUAGE_UNSUPPORTED",
                    format!(
                        "translation unit {} declares unsupported -x {language}",
                        file.display()
                    ),
                    "Provide a C, C++, or CUDA compilation command for this C-family source.",
                )),
            };
        }
        index += 1;
    }
    let extension = file
        .extension()
        .and_then(|extension| extension.to_str())
        .unwrap_or_default();
    if extension.eq_ignore_ascii_case("c") {
        Ok("c")
    } else if ["cc", "cpp", "cxx", "c++", "cu"]
        .iter()
        .any(|candidate| extension.eq_ignore_ascii_case(candidate))
    {
        Ok("c++")
    } else {
        Err(envelope(
            "ASTRO_COMPILE_CONTEXT_LANGUAGE_UNKNOWN",
            format!(
                "cannot derive C-family language for translation unit {}",
                file.display()
            ),
            "Add an exact -x language argument or use a conventional C/C++/CUDA extension.",
        ))
    }
}

fn run_context_compiler(
    arguments: &[String],
    directory: &Path,
    operation: &str,
    file: &Path,
    source_date_epoch: &str,
) -> Result<Output, BridgeError> {
    let output = Command::new(&arguments[0])
        .args(&arguments[1..])
        .current_dir(directory)
        .env("SOURCE_DATE_EPOCH", source_date_epoch)
        .stdin(Stdio::null())
        .output()
        .map_err(|error| {
            envelope(
                "ASTRO_COMPILE_CONTEXT_COMPILER_UNREACHABLE",
                format!(
                    "cannot execute compiler argv {arguments:?} in {} during {operation} for {}: {error}",
                    directory.display(),
                    file.display()
                ),
                "Restore the exact compiler named by compile_commands.json to PATH or its recorded path.",
            )
        })?;
    if output.status.success() {
        return Ok(output);
    }
    Err(BridgeError::new(
        ErrorEnvelope::new(
            "ASTRO_COMPILE_CONTEXT_COMPILER_FAILED",
            format!(
                "compiler argv {arguments:?} in {} failed during {operation} for {} with {}",
                directory.display(),
                file.display(),
                output.status
            ),
            "Read stderr, repair the real compilation command/build inputs, and regenerate the database.",
        )
        .with_stderr(String::from_utf8_lossy(&output.stderr)),
    ))
}

fn parse_compiler_baseline(
    stdout: &[u8],
    stderr: &[u8],
    file: &Path,
) -> Result<(Vec<String>, Vec<String>), BridgeError> {
    let stdout = std::str::from_utf8(stdout).map_err(|error| {
        envelope(
            "ASTRO_COMPILE_CONTEXT_PREDEFINES_UTF8_INVALID",
            format!(
                "compiler predefines for {} are not UTF-8: {error}",
                file.display()
            ),
            "Use a compiler that emits UTF-8 diagnostics and predefined macro text.",
        )
    })?;
    let stderr = std::str::from_utf8(stderr).map_err(|error| {
        envelope(
            "ASTRO_COMPILE_CONTEXT_INCLUDE_SEARCH_UTF8_INVALID",
            format!(
                "compiler include-search output for {} is not UTF-8: {error}",
                file.display()
            ),
            "Use a compiler that emits UTF-8 include-search diagnostics.",
        )
    })?;
    let predefined_macros = stdout
        .lines()
        .filter_map(|line| line.strip_prefix("#define "))
        .map(|definition| match definition.find(char::is_whitespace) {
            Some(index) => format!(
                "{}={}",
                &definition[..index],
                definition[index..].trim_start()
            ),
            None => definition.to_owned(),
        })
        .collect::<Vec<_>>();
    if predefined_macros.is_empty() {
        return Err(envelope(
            "ASTRO_COMPILE_CONTEXT_PREDEFINES_MISSING",
            format!(
                "compiler reported no predefined macros for {}",
                file.display()
            ),
            "Use a compiler driver supporting exact -dM -E preprocessing queries.",
        ));
    }
    let mut include_paths = Vec::new();
    let mut reading = false;
    for line in stderr.lines() {
        let line = line.trim();
        if line == "#include <...> search starts here:" {
            reading = true;
            continue;
        }
        if line == "End of search list." {
            break;
        }
        if reading && !line.is_empty() {
            include_paths.push(
                line.strip_suffix(" (framework directory)")
                    .unwrap_or(line)
                    .replace('\\', "/"),
            );
        }
    }
    if include_paths.is_empty() {
        return Err(envelope(
            "ASTRO_COMPILE_CONTEXT_SYSTEM_INCLUDES_MISSING",
            format!(
                "compiler reported no system include roots for {}",
                file.display()
            ),
            "Use a compiler driver supporting exact -E -v include-search queries.",
        ));
    }
    Ok((predefined_macros, include_paths))
}

fn inferred_standard(
    macros: &[String],
    language: &str,
    file: &Path,
) -> Result<String, BridgeError> {
    let macro_value = |name: &str| {
        macros.iter().find_map(|definition| {
            definition
                .strip_prefix(name)
                .and_then(|value| value.strip_prefix('='))
        })
    };
    let gnu = macro_value("__STRICT_ANSI__").is_none();
    let (base, suffix) = if language == "c++" {
        let value = macro_value("__cplusplus").ok_or_else(|| {
            envelope(
                "ASTRO_COMPILE_CONTEXT_STANDARD_FACT_MISSING",
                format!("compiler did not report __cplusplus for {}", file.display()),
                "Correct the translation-unit language/compiler command and regenerate the database.",
            )
        })?;
        let digits = value.trim_end_matches(|character: char| !character.is_ascii_digit());
        let standard = match digits.parse::<u64>().unwrap_or(0) {
            0..=201_102 => "98",
            201_103..=201_401 => "11",
            201_402..=201_702 => "14",
            201_703..=202_001 => "17",
            202_002..=202_301 => "20",
            202_302..=202_599 => "23",
            _ => "26",
        };
        (if gnu { "gnu++" } else { "c++" }, standard)
    } else {
        let value = macro_value("__STDC_VERSION__").unwrap_or("199409L");
        let digits = value.trim_end_matches(|character: char| !character.is_ascii_digit());
        let standard = match digits.parse::<u64>().unwrap_or(0) {
            0..=199_899 => "90",
            199_900..=201_111 => "99",
            201_112..=201_709 => "11",
            201_710..=202_310 => "17",
            _ => "23",
        };
        (if gnu { "gnu" } else { "c" }, standard)
    };
    Ok(format!("{base}{suffix}"))
}

fn parse_make_dependencies(
    text: &[u8],
    repo_root: &Path,
    directory: &Path,
    file: &Path,
) -> Result<Vec<String>, BridgeError> {
    let text = std::str::from_utf8(text).map_err(|error| {
        envelope(
            "ASTRO_COMPILE_CONTEXT_DEPENDENCIES_UTF8_INVALID",
            format!(
                "compiler dependencies for {} are not UTF-8: {error}",
                file.display()
            ),
            "Use a compiler that emits UTF-8 Make dependency records.",
        )
    })?;
    let text = text.replace("\\\r\n", " ").replace("\\\n", " ");
    let dependencies = text.strip_prefix("astrolabe-context:").ok_or_else(|| {
        envelope(
            "ASTRO_COMPILE_CONTEXT_DEPENDENCY_TARGET_INVALID",
            format!(
                "compiler dependency output for {} lacks the bound target",
                file.display()
            ),
            "Use a compiler supporting -M -MT astrolabe-context dependency output.",
        )
    })?;
    let mut tokens = Vec::new();
    let mut token = String::new();
    let mut characters = dependencies.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\\' {
            match characters.peek().copied() {
                Some(next) if next.is_whitespace() || next == '\\' => {
                    token.push(characters.next().expect("peeked dependency character"));
                }
                _ => token.push(character),
            }
        } else if character.is_whitespace() {
            if !token.is_empty() {
                tokens.push(std::mem::take(&mut token));
            }
        } else {
            token.push(character);
        }
    }
    if !token.is_empty() {
        tokens.push(token);
    }
    let mut relative = Vec::new();
    for token in tokens {
        let path = Path::new(&token);
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            directory.join(path)
        };
        if let Some(path) = path_within_repo(repo_root, &path) {
            relative.push(path);
        }
    }
    relative.sort();
    relative.dedup();
    let source = path_within_repo(repo_root, file).ok_or_else(|| {
        envelope(
            "ASTRO_COMPILE_CONTEXT_TU_OUTSIDE_REPOSITORY",
            format!(
                "translation unit {} is outside the repository",
                file.display()
            ),
            "Regenerate compile_commands.json for the indexed repository root.",
        )
    })?;
    if !relative.iter().any(|dependency| dependency == &source) {
        return Err(envelope(
            "ASTRO_COMPILE_CONTEXT_DEPENDENCY_TU_MISSING",
            format!("compiler dependency closure omits translation unit {source}"),
            "Repair the compiler dependency output before indexing.",
        ));
    }
    Ok(relative)
}

fn capture_repository_compile_command(
    repo_root: &Path,
    entry: &serde_json::Value,
    baseline_cache: &mut BTreeMap<(String, Vec<String>), usize>,
    baselines: &mut Vec<RepositoryCompilerBaseline>,
    baseline_reuses: &mut usize,
    source_date_epoch: &RepositorySourceDateEpoch,
) -> Result<Option<RepositoryCompileCommand>, BridgeError> {
    let file_text = entry
        .get("file")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            envelope(
                "ASTRO_COMPILE_CONTEXT_FILE_MISSING",
                "a compilation database entry has no file",
                "Regenerate compile_commands.json with complete entries.",
            )
        })?;
    let directory_text = entry
        .get("directory")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            envelope(
                "ASTRO_COMPILE_CONTEXT_DIRECTORY_MISSING",
                format!("compilation command for {file_text} has no directory"),
                "Regenerate compile_commands.json with an exact working directory per entry.",
            )
        })?;
    let directory = canonical_path(
        Path::new(directory_text),
        "ASTRO_COMPILE_CONTEXT_DIRECTORY_UNRESOLVED",
        "compilation working directory",
    )?;
    let file_path = Path::new(file_text);
    let file_path = if file_path.is_absolute() {
        file_path.to_path_buf()
    } else {
        directory.join(file_path)
    };
    let file_path = canonical_path(
        &file_path,
        "ASTRO_COMPILE_CONTEXT_FILE_UNRESOLVED",
        "translation unit",
    )?;
    let Some(file) = path_within_repo(repo_root, &file_path) else {
        return Ok(None);
    };
    let mut arguments = command_entry_arguments(entry, &file)?;
    let language = translation_unit_language(&arguments, &file_path)?;

    let mut baseline_arguments =
        context_compiler_arguments(&arguments, &directory, &file_path, false, false)?;
    baseline_arguments.extend([
        "-dM".to_owned(),
        "-E".to_owned(),
        "-v".to_owned(),
        "-x".to_owned(),
        language.to_owned(),
        "-".to_owned(),
    ]);
    // Compiler predefines and system roots depend on the exact cwd + argv, not
    // on the translation-unit bytes (which have been removed from this query).
    // Reuse only that complete identity: distinct flags, compilers, languages,
    // or relative-path working directories remain separate queries.
    let baseline_key = (normalized_path(&directory), baseline_arguments.clone());
    let baseline_index = if let Some(index) = baseline_cache.get(&baseline_key).copied() {
        *baseline_reuses = (*baseline_reuses).checked_add(1).ok_or_else(|| {
            envelope(
                "ASTRO_COMPILE_CONTEXT_REUSE_OVERFLOW",
                "compiler baseline reuse telemetry exceeds usize representation",
                "Reduce the compilation database size or extend telemetry representation.",
            )
        })?;
        index
    } else {
        let baseline_output = run_context_compiler(
            &baseline_arguments,
            &directory,
            "baseline query",
            &file_path,
            &source_date_epoch.value,
        )?;
        let (predefined_macros, system_include_paths) =
            parse_compiler_baseline(&baseline_output.stdout, &baseline_output.stderr, &file_path)?;
        let index = baselines.len();
        baselines.push(RepositoryCompilerBaseline {
            predefined_macros,
            system_include_paths,
        });
        baseline_cache.insert(baseline_key, index);
        index
    };
    let baseline = &baselines[baseline_index];
    if !arguments
        .iter()
        .any(|argument| argument.starts_with("-std="))
    {
        arguments.push(format!(
            "-std={}",
            inferred_standard(&baseline.predefined_macros, language, &file_path)?
        ));
    }

    // Persist the compiler driver's exact non-action argument frame separately.
    // The native pipeline substitutes only its immutable snapshot TU and adds
    // `-E`; it never has to reinterpret output/dependency switches or guess
    // which argv element names the translation unit.
    let preprocess_arguments =
        context_compiler_arguments(&arguments, &directory, &file_path, true, false)?;

    let mut dependency_arguments =
        context_compiler_arguments(&arguments, &directory, &file_path, true, true)?;
    dependency_arguments.extend([
        "-M".to_owned(),
        "-MT".to_owned(),
        "astrolabe-context".to_owned(),
    ]);
    let dependency_output = run_context_compiler(
        &dependency_arguments,
        &directory,
        "dependency closure",
        &file_path,
        &source_date_epoch.value,
    )?;
    let dependencies =
        parse_make_dependencies(&dependency_output.stdout, repo_root, &directory, &file_path)?;
    Ok(Some(RepositoryCompileCommand {
        file,
        language,
        directory: normalized_path(&directory),
        arguments,
        preprocess_arguments,
        dependencies,
        baseline_index,
    }))
}

fn compilation_context_for_repo(repo_path: &str) -> Result<Vec<u8>, BridgeError> {
    let repo_root = canonical_path(
        Path::new(repo_path),
        "ASTRO_COMPILE_CONTEXT_REPOSITORY_UNRESOLVED",
        "repository root",
    )?;
    let embedded: serde_json::Value =
        serde_json::from_slice(cbm_sys::ASTROLABE_BUILD_COMPILATION_CONTEXT).map_err(|error| {
            envelope(
                "ASTRO_COMPILE_CONTEXT_EMBEDDED_MALFORMED",
                format!("artifact compilation context is malformed: {error}"),
                "Rebuild Astrolabe from the canonical source tree.",
            )
        })?;
    if embedded
        .get("source_root")
        .and_then(serde_json::Value::as_str)
        .and_then(|source_root| Path::new(source_root).canonicalize().ok())
        .is_some_and(|source_root| source_root == repo_root)
    {
        let embedded_json = std::str::from_utf8(cbm_sys::ASTROLABE_BUILD_COMPILATION_CONTEXT)
            .map_err(|error| {
                envelope(
                    "ASTRO_COMPILE_CONTEXT_EMBEDDED_UTF8_INVALID",
                    format!("artifact compilation context is not UTF-8: {error}"),
                    "Rebuild Astrolabe from the canonical source tree.",
                )
            })?;
        validate_bound_compilation_context(repo_path, embedded_json, true)?;
        return Ok(cbm_sys::ASTROLABE_BUILD_COMPILATION_CONTEXT.to_vec());
    }

    let database_path = repo_root.join("compile_commands.json");
    if !database_path.exists() {
        // Bind absence to this exact repository instead of substituting the
        // artifact's unrelated canonical context. Discovered C-family atoms
        // remain visible with an explicit configuration-absent state and no
        // invented compiler semantics or contextual call facts.
        return serde_json::to_vec(&serde_json::json!({
            "format": "astrolabe.compilation-context.v1",
            "source_root": normalized_path(&repo_root),
            "authority": "absent",
            "baselines": [],
            "commands": [],
        }))
        .map_err(|error| {
            envelope(
                "ASTRO_COMPILE_CONTEXT_SERIALIZE_FAILED",
                format!("cannot serialize absent compilation-context authority: {error}"),
                "Preserve the repository root and report this deterministic serialization fault.",
            )
        });
    }
    let bytes = fs::read(&database_path).map_err(|error| {
        envelope(
            "ASTRO_COMPILE_CONTEXT_DATABASE_READ_FAILED",
            format!("cannot read {}: {error}", database_path.display()),
            "Restore the exact compilation database bytes and retry the unchanged corpus.",
        )
    })?;
    let document: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
        envelope(
            "ASTRO_COMPILE_CONTEXT_DATABASE_MALFORMED",
            format!("{} is not valid JSON: {error}", database_path.display()),
            "Regenerate compile_commands.json from a successful real build.",
        )
    })?;
    let entries = document.as_array().ok_or_else(|| {
        envelope(
            "ASTRO_COMPILE_CONTEXT_DATABASE_SCHEMA_INVALID",
            format!("{} is not a JSON array", database_path.display()),
            "Regenerate the database according to the JSON Compilation Database format.",
        )
    })?;
    if entries.is_empty() {
        return Err(envelope(
            "ASTRO_COMPILE_CONTEXT_DATABASE_EMPTY",
            format!(
                "{} contains no translation-unit commands",
                database_path.display()
            ),
            "Run the real build's compilation-database generator and retry.",
        ));
    }
    let source_date_epoch = repository_source_date_epoch(&repo_root)?;
    let mut captured = Vec::new();
    let mut baseline_cache = BTreeMap::new();
    let mut compiler_baselines = Vec::new();
    let mut baseline_reuses = 0usize;
    for entry in entries {
        if let Some(command) = capture_repository_compile_command(
            &repo_root,
            entry,
            &mut baseline_cache,
            &mut compiler_baselines,
            &mut baseline_reuses,
            &source_date_epoch,
        )? {
            captured.push(command);
        }
    }
    if captured.is_empty() {
        return Err(envelope(
            "ASTRO_COMPILE_CONTEXT_DATABASE_NO_REPOSITORY_TUS",
            format!(
                "{} contains no translation unit under {}",
                database_path.display(),
                repo_root.display()
            ),
            "Generate compile_commands.json for the exact repository being indexed.",
        ));
    }
    let source_date_epoch_readback = repository_source_date_epoch_with_root(
        &repo_root,
        Some(Path::new(&source_date_epoch.repository_root)),
    )?;
    if source_date_epoch_readback != source_date_epoch {
        return Err(envelope(
            "ASTRO_COMPILE_CONTEXT_SOURCE_EPOCH_DRIFT",
            format!(
                "Git source epoch changed while capturing compilation context for {}: before={source_date_epoch:?}, after={source_date_epoch_readback:?}",
                repo_root.display()
            ),
            "Let the repository update finish, then retry one unchanged source generation.",
        ));
    }
    captured.sort_by(|left, right| {
        left.file
            .cmp(&right.file)
            .then_with(|| left.arguments.cmp(&right.arguments))
    });

    let mut baseline_ids = BTreeMap::<Vec<String>, String>::new();
    let mut serialized_baselines = Vec::new();
    let mut commands = Vec::new();
    for command in captured {
        let baseline = &compiler_baselines[command.baseline_index];
        let mut key = baseline.predefined_macros.clone();
        key.push("\0includes\0".to_owned());
        key.extend(baseline.system_include_paths.clone());
        let baseline_id = if let Some(id) = baseline_ids.get(&key) {
            id.clone()
        } else {
            let id = format!("repository-baseline-{:03}", baseline_ids.len());
            serialized_baselines.push(serde_json::json!({
                "id": id,
                "predefined_macros": &baseline.predefined_macros,
                "system_include_paths": &baseline.system_include_paths,
            }));
            baseline_ids.insert(key, id.clone());
            id
        };
        commands.push(serde_json::json!({
            "file": command.file,
            "language": command.language,
            "directory": command.directory,
            "arguments": command.arguments,
            "preprocess_arguments": command.preprocess_arguments,
            "baseline_id": baseline_id,
            "dependencies": command.dependencies,
        }));
    }
    serde_json::to_vec(&serde_json::json!({
        "format": "astrolabe.compilation-context.v1",
        "source_root": normalized_path(&repo_root),
        "source_date_epoch": {
            "value": source_date_epoch.value,
            "provenance": "git_head_commit",
            "revision": source_date_epoch.revision,
            "repository_root": source_date_epoch.repository_root,
        },
        "capture": {
            "baseline_queries": compiler_baselines.len(),
            "baseline_reuses": baseline_reuses,
        },
        "baselines": serialized_baselines,
        "commands": commands,
    }))
    .map_err(|error| {
        envelope(
            "ASTRO_COMPILE_CONTEXT_SERIALIZE_FAILED",
            format!("cannot serialize immutable repository compilation context: {error}"),
            "Preserve the compilation database and report this deterministic serialization fault.",
        )
    })
}

/// Private Rust-host transport field carrying one complete immutable
/// `astrolabe.compilation-context.v1` document. It is attached only at the
/// final Rust→CBM boundary, so it never enters persisted public tool arguments.
pub const ASTRO_COMPILATION_CONTEXT_ARG: &str = "_astrolabe_compilation_context_json";

fn validate_bound_compilation_context(
    repo_path: &str,
    context_json: &str,
    verify_git_epoch: bool,
) -> Result<(), BridgeError> {
    let repo_root = canonical_path(
        Path::new(repo_path),
        "ASTRO_COMPILE_CONTEXT_REPOSITORY_UNRESOLVED",
        "repository root",
    )?;
    let value: serde_json::Value = serde_json::from_str(context_json).map_err(|error| {
        envelope(
            "ASTRO_COMPILE_CONTEXT_TRANSPORT_MALFORMED",
            format!("private compilation-context transport is not valid JSON: {error}"),
            "Preserve the worker argument file and regenerate it from the exact parent request.",
        )
    })?;
    if value.get("format").and_then(serde_json::Value::as_str)
        != Some("astrolabe.compilation-context.v1")
    {
        return Err(envelope(
            "ASTRO_COMPILE_CONTEXT_TRANSPORT_SCHEMA_INVALID",
            "private compilation-context transport has an unsupported format",
            "Regenerate the worker arguments with this Astrolabe artifact.",
        ));
    }
    let source_root = value
        .get("source_root")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            envelope(
                "ASTRO_COMPILE_CONTEXT_TRANSPORT_SOURCE_MISSING",
                "private compilation-context transport has no source_root",
                "Regenerate the worker arguments from the exact repository root.",
            )
        })?;
    let transported_root = canonical_path(
        Path::new(source_root),
        "ASTRO_COMPILE_CONTEXT_TRANSPORT_SOURCE_UNRESOLVED",
        "transported compilation-context source root",
    )?;
    if transported_root != repo_root {
        return Err(envelope(
            "ASTRO_COMPILE_CONTEXT_TRANSPORT_SOURCE_MISMATCH",
            format!(
                "private compilation context names {}, but this request indexes {}",
                transported_root.display(),
                repo_root.display()
            ),
            "Discard the mismatched worker request and regenerate it for the exact repository.",
        ));
    }
    for field in ["baselines", "commands"] {
        if !value.get(field).is_some_and(serde_json::Value::is_array) {
            return Err(envelope(
                "ASTRO_COMPILE_CONTEXT_TRANSPORT_SCHEMA_INVALID",
                format!("private compilation-context transport field {field:?} is not an array"),
                "Regenerate the worker arguments with this Astrolabe artifact.",
            ));
        }
    }
    if let Some(authority) = value.get("authority") {
        if authority.as_str() != Some("absent") {
            return Err(envelope(
                "ASTRO_COMPILE_CONTEXT_AUTHORITY_INVALID",
                "private compilation-context transport has an unsupported authority marker",
                "Regenerate the worker arguments with this Astrolabe artifact.",
            ));
        }
        let baselines_empty = value
            .get("baselines")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|items| items.is_empty());
        let commands_empty = value
            .get("commands")
            .and_then(serde_json::Value::as_array)
            .is_some_and(|items| items.is_empty());
        if !baselines_empty
            || !commands_empty
            || value.get("capture").is_some()
            || value.get("source_date_epoch").is_some()
        {
            return Err(envelope(
                "ASTRO_COMPILE_CONTEXT_ABSENCE_CONTRADICTORY",
                "absent compilation-context authority carries compiler state",
                "Preserve the contradictory manifest and regenerate it from one repository state.",
            ));
        }
    } else {
        let source_date_epoch = value
            .get("source_date_epoch")
            .and_then(serde_json::Value::as_object)
            .ok_or_else(|| {
                envelope(
                    "ASTRO_COMPILE_CONTEXT_SOURCE_EPOCH_MISSING",
                    "active compilation-context transport has no source_date_epoch object",
                    "Regenerate the compilation context from the exact committed Git repository.",
                )
            })?;
        let epoch = source_date_epoch
            .get("value")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let revision = source_date_epoch
            .get("revision")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        let repository_root = source_date_epoch
            .get("repository_root")
            .and_then(serde_json::Value::as_str)
            .unwrap_or_default();
        if source_date_epoch
            .get("provenance")
            .and_then(serde_json::Value::as_str)
            != Some("git_head_commit")
            || epoch.is_empty()
            || !epoch.bytes().all(|byte| byte.is_ascii_digit())
            || (epoch.len() > 1 && epoch.starts_with('0'))
            || epoch.parse::<u64>().is_err()
            || !matches!(revision.len(), 40 | 64)
            || !revision.bytes().all(|byte| byte.is_ascii_hexdigit())
            || repository_root.is_empty()
        {
            return Err(envelope(
                "ASTRO_COMPILE_CONTEXT_SOURCE_EPOCH_INVALID",
                "active compilation-context transport has invalid source-date provenance",
                "Regenerate the compilation context from the exact committed Git repository.",
            ));
        }
        let transported_repository_root = canonical_path(
            Path::new(repository_root),
            "ASTRO_COMPILE_CONTEXT_SOURCE_EPOCH_REPOSITORY_UNRESOLVED",
            "transported source-date Git repository root",
        )?;
        if !repo_root.starts_with(&transported_repository_root) {
            return Err(envelope(
                "ASTRO_COMPILE_CONTEXT_SOURCE_EPOCH_REPOSITORY_MISMATCH",
                format!(
                    "indexed root {} is not within transported Git root {}",
                    repo_root.display(),
                    transported_repository_root.display()
                ),
                "Discard the mismatched worker request and regenerate it for the exact repository.",
            ));
        }
        if verify_git_epoch {
            let observed = repository_source_date_epoch_with_root(
                &repo_root,
                Some(&transported_repository_root),
            )?;
            if epoch != observed.value
                || !revision.eq_ignore_ascii_case(&observed.revision)
                || transported_repository_root
                    != canonical_path(
                        Path::new(&observed.repository_root),
                        "ASTRO_COMPILE_CONTEXT_SOURCE_EPOCH_REPOSITORY_UNRESOLVED",
                        "observed source-date Git repository root",
                    )?
            {
                return Err(envelope(
                    "ASTRO_COMPILE_CONTEXT_SOURCE_EPOCH_DRIFT",
                    format!(
                        "transported source epoch ({epoch}, {revision}, {}) no longer matches Git ({}, {}, {})",
                        transported_repository_root.display(),
                        observed.value,
                        observed.revision,
                        observed.repository_root
                    ),
                    "Discard the stale worker request and retry one unchanged Git source generation.",
                ));
            }
        }
    }
    Ok(())
}

fn bind_compilation_context_to_index_args(args_json: &str) -> Result<String, BridgeError> {
    let mut value: serde_json::Value = serde_json::from_str(args_json).map_err(|error| {
        envelope(
            "ASTRO_COMPILE_CONTEXT_ARGS_MALFORMED",
            format!("index_repository arguments are not valid JSON: {error}"),
            "Pass one JSON object containing the exact repo_path.",
        )
    })?;
    let object = value.as_object_mut().ok_or_else(|| {
        envelope(
            "ASTRO_COMPILE_CONTEXT_ARGS_OBJECT_REQUIRED",
            "index_repository arguments must be a JSON object",
            "Pass one JSON object containing the exact repo_path.",
        )
    })?;
    let repo_path = object
        .get("repo_path")
        .and_then(serde_json::Value::as_str)
        .ok_or_else(|| {
            envelope(
                "ASTRO_COMPILE_CONTEXT_REPOSITORY_REQUIRED",
                "index_repository requires a string repo_path before context binding",
                "Pass the existing repository root in repo_path.",
            )
        })?
        .to_owned();
    if object.get("mode").and_then(serde_json::Value::as_str) == Some("cross-repo-intelligence") {
        return Ok(args_json.to_owned());
    }
    if let Some(existing) = object.get(ASTRO_COMPILATION_CONTEXT_ARG) {
        let context_json = existing.as_str().ok_or_else(|| {
            envelope(
                "ASTRO_COMPILE_CONTEXT_TRANSPORT_TYPE_INVALID",
                "private compilation-context transport is not a string",
                "Preserve the worker argument file and regenerate it from the exact parent request.",
            )
        })?;
        validate_bound_compilation_context(&repo_path, context_json, true)?;
        return Ok(args_json.to_owned());
    }
    let context = compilation_context_for_repo(&repo_path)?;
    let context_json = String::from_utf8(context).map_err(|error| {
        envelope(
            "ASTRO_COMPILE_CONTEXT_TRANSPORT_UTF8_INVALID",
            format!("generated compilation context is not UTF-8: {error}"),
            "Preserve the compilation database and report this serialization fault.",
        )
    })?;
    validate_bound_compilation_context(&repo_path, &context_json, false)?;
    object.insert(
        ASTRO_COMPILATION_CONTEXT_ARG.to_owned(),
        serde_json::Value::String(context_json),
    );
    serde_json::to_string(&value).map_err(|error| {
        envelope(
            "ASTRO_COMPILE_CONTEXT_ARGS_SERIALIZE_FAILED",
            format!("cannot serialize context-bound index arguments: {error}"),
            "Preserve the original request and report this deterministic serialization fault.",
        )
    })
}

pub struct CbmPipeline {
    ptr: NonNull<cbm_sys::cbm_pipeline_t>,
    owner: ThreadId,
    _repo_path: CString,
    _db_path: CString,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl CbmPipeline {
    pub fn new(repo_path: &str, db_path: &str, mode: CbmIndexMode) -> Result<Self, BridgeError> {
        initialize_cbm_allocator()?;
        let compilation_context = compilation_context_for_repo(repo_path)?;
        let repo_path = CString::new(repo_path)?;
        let db_path = CString::new(db_path)?;
        // SAFETY: cbm_init is idempotent in libcbm. The repo/db strings outlive
        // pipeline creation and CBM copies the paths into the pipeline object.
        unsafe {
            map_cbm_status(cbm_sys::cbm_init())?;
            let ptr =
                cbm_sys::cbm_pipeline_new(repo_path.as_ptr(), db_path.as_ptr(), mode.as_raw());
            let ptr = NonNull::new(ptr).ok_or_else(|| {
                envelope(
                    "ASTRO_CBM_PIPELINE_INIT",
                    "cbm_pipeline_new returned NULL",
                    "Check repository path validity and CBM startup diagnostics.",
                )
            })?;
            if let Err(error) =
                map_cbm_status(cbm_sys::cbm_pipeline_set_embedded_compilation_context(
                    ptr.as_ptr(),
                    compilation_context.as_ptr(),
                    compilation_context.len(),
                ))
            {
                cbm_sys::cbm_pipeline_free(ptr.as_ptr());
                return Err(error);
            }
            Ok(Self {
                ptr,
                owner: thread::current().id(),
                _repo_path: repo_path,
                _db_path: db_path,
                _not_send_or_sync: PhantomData,
            })
        }
    }

    pub fn collect_rows(&mut self) -> Result<CbmPipelineRows, BridgeError> {
        self.ensure_owner_thread()?;
        let mut sink = PipelineRowSinkState::new();
        let descriptor = pipeline_row_sink_descriptor(&mut sink);
        // SAFETY: self owns the pipeline pointer. `sink` remains live until
        // cbm_pipeline_run returns, and the sink is cleared immediately after.
        let rc = unsafe {
            map_cbm_status(cbm_sys::cbm_pipeline_set_sink(
                self.ptr.as_ptr(),
                &descriptor,
            ))?;
            let rc = cbm_sys::cbm_pipeline_run(self.ptr.as_ptr());
            map_cbm_status(cbm_sys::cbm_pipeline_set_sink(
                self.ptr.as_ptr(),
                ptr::null(),
            ))?;
            rc
        };

        if rc != 0 {
            if let Some(error) = sink.error {
                return Err(error);
            }
            map_cbm_status(rc)?;
        }
        let project = self.project_name()?;
        finish_pipeline_rows(sink, project)
    }

    pub fn collect_rows_with_post_success_response(
        &mut self,
        response_tmp: &Path,
        response_path: &Path,
    ) -> Result<CbmPipelineRows, BridgeError> {
        self.ensure_owner_thread()?;
        let mut sink = PipelineRowSinkState::new_with_success_publisher(
            response_tmp.to_path_buf(),
            response_path.to_path_buf(),
        );
        let descriptor = pipeline_row_sink_descriptor(&mut sink);
        // SAFETY: self owns the pipeline pointer. `sink` remains live until
        // cbm_pipeline_run returns; the post-success callback only writes the
        // already-copied row-sink snapshot after CBM has reached its success
        // postcondition and before native teardown begins.
        let rc = unsafe {
            map_cbm_status(cbm_sys::cbm_pipeline_set_sink(
                self.ptr.as_ptr(),
                &descriptor,
            ))?;
            map_cbm_status(cbm_sys::cbm_pipeline_set_post_success_callback(
                self.ptr.as_ptr(),
                Some(pipeline_post_success_sink),
                (&mut sink as *mut PipelineRowSinkState).cast::<c_void>(),
            ))?;
            let rc = cbm_sys::cbm_pipeline_run(self.ptr.as_ptr());
            map_cbm_status(cbm_sys::cbm_pipeline_set_post_success_callback(
                self.ptr.as_ptr(),
                None,
                ptr::null_mut(),
            ))?;
            map_cbm_status(cbm_sys::cbm_pipeline_set_sink(
                self.ptr.as_ptr(),
                ptr::null(),
            ))?;
            rc
        };

        if rc != 0 {
            if let Some(error) = sink.error {
                return Err(error);
            }
            map_cbm_status(rc)?;
        }
        if !response_path.exists() {
            return Err(envelope(
                "ASTRO_CBM_ROW_SINK_SUCCESS_RESPONSE_MISSING",
                format!(
                    "CBM reported success but post-success response {} is absent",
                    response_path.display()
                ),
                "Do not trust a cleanup-dependent worker success; inspect the post-success callback path.",
            ));
        }
        let project = self.project_name()?;
        finish_pipeline_rows(sink, project)
    }

    pub fn run_to_sqlite(&mut self) -> Result<(), BridgeError> {
        self.ensure_owner_thread()?;
        // SAFETY: self owns the pipeline pointer. Clearing the sink first makes
        // this the baseline no-row-sink path for benchmark and compatibility use.
        let rc = unsafe {
            map_cbm_status(cbm_sys::cbm_pipeline_set_sink(
                self.ptr.as_ptr(),
                ptr::null(),
            ))?;
            cbm_sys::cbm_pipeline_run(self.ptr.as_ptr())
        };
        map_cbm_status(rc)
    }

    pub fn bind_project_identity_root(
        &mut self,
        identity_root: &str,
        expected_project: &str,
    ) -> Result<(), BridgeError> {
        self.ensure_owner_thread()?;
        let identity_root = CString::new(identity_root)?;
        // SAFETY: self owns the pipeline pointer. CBM resolves the supplied
        // existing repository root and derives the project identity from it.
        let accepted = unsafe {
            cbm_sys::cbm_pipeline_set_project_identity_root(
                self.ptr.as_ptr(),
                identity_root.as_ptr(),
            )
        };
        if !accepted {
            return Err(envelope(
                "ASTRO_CBM_PIPELINE_PROJECT_IDENTITY_ROOT",
                "CBM could not derive project identity from the supplied repository root",
                "Pass the existing durable repository root that owns this controlled checkout.",
            ));
        }
        let observed = self.project_name()?;
        if observed != expected_project {
            return Err(envelope(
                "ASTRO_CBM_PIPELINE_PROJECT_IDENTITY_MISMATCH",
                format!(
                    "root-derived project identity {observed:?} does not match expected \
                     identity {expected_project:?}"
                ),
                "Bind the scratch extraction to the exact durable corpus root used by the live index.",
            ));
        }
        Ok(())
    }

    pub fn project_name(&self) -> Result<String, BridgeError> {
        self.ensure_owner_thread()?;
        // SAFETY: self owns the pipeline pointer; CBM returns a borrowed
        // NUL-terminated string valid until cbm_pipeline_free.
        let ptr = unsafe { cbm_sys::cbm_pipeline_project_name(self.ptr.as_ptr()) };
        required_borrowed_c_string(ptr, "pipeline.project_name")
    }

    fn ensure_owner_thread(&self) -> Result<(), BridgeError> {
        if thread::current().id() == self.owner {
            Ok(())
        } else {
            Err(envelope(
                "ASTRO_CBM_THREAD_AFFINITY",
                "CbmPipeline used from a different thread than the creating thread",
                "Create one CbmPipeline per thread; do not share cbm_pipeline_t across threads.",
            ))
        }
    }
}

impl Drop for CbmPipeline {
    fn drop(&mut self) {
        // SAFETY: self uniquely owns the cbm_pipeline_t pointer.
        unsafe {
            cbm_sys::cbm_pipeline_free(self.ptr.as_ptr());
        }
    }
}

unsafe extern "C" fn pipeline_node_sink(
    node: *const cbm_sys::cbm_gbuf_row_node_t,
    ctx: *mut c_void,
) -> c_int {
    let Some(state) = (unsafe { (ctx as *mut PipelineRowSinkState).as_mut() }) else {
        return CALLBACK_ERROR;
    };
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let node = unsafe { node.as_ref() }.ok_or_else(|| {
            envelope(
                "ASTRO_CBM_ROW_SINK_NULL_NODE",
                "CBM row-sink node callback received NULL",
                "Treat this as FFI contract drift; callbacks require a borrowed row pointer.",
            )
        })?;
        state.push_node(node)
    }));
    state.finish_callback(result)
}

unsafe extern "C" fn pipeline_edge_sink(
    edge: *const cbm_sys::cbm_gbuf_row_edge_t,
    ctx: *mut c_void,
) -> c_int {
    let Some(state) = (unsafe { (ctx as *mut PipelineRowSinkState).as_mut() }) else {
        return CALLBACK_ERROR;
    };
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let edge = unsafe { edge.as_ref() }.ok_or_else(|| {
            envelope(
                "ASTRO_CBM_ROW_SINK_NULL_EDGE",
                "CBM row-sink edge callback received NULL",
                "Treat this as FFI contract drift; callbacks require a borrowed row pointer.",
            )
        })?;
        state.push_edge(edge)
    }));
    state.finish_callback(result)
}

unsafe extern "C" fn pipeline_file_hash_sink(
    file_hash: *const cbm_sys::cbm_pipeline_row_file_hash_t,
    ctx: *mut c_void,
) -> c_int {
    let Some(state) = (unsafe { (ctx as *mut PipelineRowSinkState).as_mut() }) else {
        return CALLBACK_ERROR;
    };
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let file_hash = unsafe { file_hash.as_ref() }.ok_or_else(|| {
            envelope(
                "ASTRO_CBM_ROW_SINK_NULL_FILE_HASH",
                "CBM row-sink file-hash callback received NULL",
                "Treat this as FFI contract drift; callbacks require a borrowed row pointer.",
            )
        })?;
        state.push_file_hash(file_hash)
    }));
    state.finish_callback(result)
}

unsafe extern "C" fn pipeline_complete_sink(
    manifest: *const cbm_sys::cbm_pipeline_row_manifest_t,
    ctx: *mut c_void,
) -> c_int {
    let Some(state) = (unsafe { (ctx as *mut PipelineRowSinkState).as_mut() }) else {
        return CALLBACK_ERROR;
    };
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
        let manifest = unsafe { manifest.as_ref() }.ok_or_else(|| {
            envelope(
                "ASTRO_CBM_ROW_SINK_NULL_MANIFEST",
                "CBM row-sink completion callback received NULL",
                "Treat this as FFI contract drift; completion requires a borrowed manifest pointer.",
            )
        })?;
        state.complete(manifest)
    }));
    state.finish_callback(result)
}

unsafe extern "C" fn pipeline_post_success_sink(ctx: *mut c_void) -> c_int {
    let Some(state) = (unsafe { (ctx as *mut PipelineRowSinkState).as_mut() }) else {
        return CALLBACK_ERROR;
    };
    let result = std::panic::catch_unwind(AssertUnwindSafe(|| state.publish_success_response()));
    state.finish_callback(result)
}

fn pipeline_row_sink_descriptor(
    state: &mut PipelineRowSinkState,
) -> cbm_sys::cbm_pipeline_row_sink_v2_t {
    cbm_sys::cbm_pipeline_row_sink_v2_t {
        abi_version: cbm_sys::CBM_PIPELINE_ROW_SINK_ABI_V2,
        struct_size: std::mem::size_of::<cbm_sys::cbm_pipeline_row_sink_v2_t>(),
        node: Some(pipeline_node_sink),
        edge: Some(pipeline_edge_sink),
        file_hash: Some(pipeline_file_hash_sink),
        complete: Some(pipeline_complete_sink),
        ctx: (state as *mut PipelineRowSinkState).cast::<c_void>(),
    }
}

fn finish_pipeline_rows(
    sink: PipelineRowSinkState,
    project: String,
) -> Result<CbmPipelineRows, BridgeError> {
    if let Some(error) = sink.error {
        return Err(error);
    }
    let manifest = sink.manifest.ok_or_else(|| {
        envelope(
            "ASTRO_CBM_ROW_SINK_INCOMPLETE",
            "CBM pipeline returned without a completion manifest",
            "Repair the native pipeline route so every successful full, incremental, and no-op snapshot emits completion.",
        )
    })?;
    if manifest.project != project {
        return Err(envelope(
            "ASTRO_CBM_ROW_SINK_PROJECT_MISMATCH",
            format!(
                "CBM tool reported project {project:?}, but the completed row snapshot belongs to {:?}",
                manifest.project
            ),
            "Publish and import one identically named project snapshot.",
        ));
    }
    Ok(CbmPipelineRows {
        project,
        nodes: sink.nodes,
        edges: sink.edges,
        file_hashes: sink.file_hashes,
        manifest: Some(manifest),
    })
}

pub struct ExtractedFile {
    ptr: NonNull<cbm_sys::CBMFileResult>,
    _source: Vec<u8>,
    _project: CString,
    _rel_path: CString,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl ExtractedFile {
    /// Extract one file without declaring any C-family compilation-context
    /// state.
    ///
    /// The `None` handoff below is the literal "no state declared" case: a
    /// C/C++/CUDA input refuses with `CBM_PREPROCESS_CONTEXT_REQUIRED` instead
    /// of being extracted against guessed host flags. That refusal is the
    /// #969 guarantee and is preserved here deliberately; migrating this
    /// entrypoint's callers (`migration::guard`) to a declared state is #1062,
    /// out of scope for #1061.
    pub fn extract(
        source: &str,
        language: Language,
        project: &str,
        rel_path: &str,
        timeout_micros: i64,
    ) -> Result<Self, BridgeError> {
        Self::extract_with_declared_contexts(
            source,
            language,
            project,
            rel_path,
            false,
            timeout_micros,
            None,
        )
    }

    /// Extract one historical/standalone blob that has no build database.
    ///
    /// The explicit empty set (`items: NULL, count: 0`) declares the
    /// **configuration-absent** state to libcbm (#1061): the caller has looked
    /// and no real build configuration consumes this source, so there is
    /// nothing to bind. libcbm retains definitions and imports and labels the
    /// file `CBM_COMPILE_CONTEXT_CONFIGURATION_ABSENT` while dropping raw call
    /// views — a counted, labeled degradation, never an invented host context.
    /// Passing `NULL` here instead would be the "caller forgot to thread
    /// context" state and would refuse every C-family input; guessing flags
    /// would violate the no-silent-fallback invariant. Callers that read only
    /// `imports()`/`definitions()` (the archaeology dependency planner) lose
    /// nothing measurable.
    pub fn extract_with_rust_context(
        source: &str,
        language: Language,
        project: &str,
        rel_path: &str,
        rust_is_crate_root: bool,
        timeout_micros: i64,
    ) -> Result<Self, BridgeError> {
        let configuration_absent = cbm_sys::CBMPreprocessContextSet {
            items: ptr::null(),
            count: 0,
        };
        Self::extract_with_declared_contexts(
            source,
            language,
            project,
            rel_path,
            rust_is_crate_root,
            timeout_micros,
            Some(&configuration_absent),
        )
    }

    /// Shared extraction body. `preprocess_contexts` is the caller's declared
    /// C-family compilation-context state and is forwarded verbatim: `None`
    /// becomes the C `NULL` (no state declared), `Some(set)` becomes a pointer
    /// to that exact set. Nothing is defaulted on either side of the FFI
    /// boundary.
    fn extract_with_declared_contexts(
        source: &str,
        language: Language,
        project: &str,
        rel_path: &str,
        rust_is_crate_root: bool,
        timeout_micros: i64,
        preprocess_contexts: Option<&cbm_sys::CBMPreprocessContextSet>,
    ) -> Result<Self, BridgeError> {
        initialize_cbm_allocator()?;
        let source_len = c_int::try_from(source.len()).map_err(|_| {
            envelope(
                "ASTRO_CBM_SOURCE_TOO_LARGE",
                "source length does not fit the CBM C API",
                "Split or reject files larger than i32::MAX bytes before extraction.",
            )
        })?;
        let source = source.as_bytes().to_vec();
        let project = CString::new(project)?;
        let rel_path = CString::new(rel_path)?;

        let preprocess_contexts = preprocess_contexts.map_or(ptr::null(), |set| {
            set as *const cbm_sys::CBMPreprocessContextSet
        });

        // SAFETY: cbm_init is idempotent in libcbm. The C strings outlive the call,
        // source is passed with an explicit byte length, and preprocess_contexts
        // borrows the caller's live set for the duration of this synchronous call.
        unsafe {
            map_cbm_status(cbm_sys::cbm_init())?;
            let ptr = cbm_sys::cbm_extract_file_at_path_with_rust_edition_context(
                source.as_ptr().cast::<c_char>(),
                source_len,
                language.as_raw(),
                project.as_ptr(),
                rel_path.as_ptr(),
                ptr::null(),
                ptr::null(),
                rust_is_crate_root,
                timeout_micros,
                preprocess_contexts,
            );
            let extracted = Self {
                ptr: NonNull::new(ptr).ok_or_else(|| {
                    envelope(
                        "ASTRO_CBM_NULL_RESULT",
                        "CBM Rust-context extraction returned NULL",
                        "Check libcbm diagnostics and reject the file as an extraction failure.",
                    )
                })?,
                _source: source,
                _project: project,
                _rel_path: rel_path,
                _not_send_or_sync: PhantomData,
            };
            if extracted.raw().has_error {
                let raw = extracted.raw();
                let code = extracted
                    .optional_string(raw.error.code)?
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| "ASTRO_CBM_EXTRACT_ERROR".to_string());
                let operation = extracted
                    .optional_string(raw.error.operation)?
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| "cbm_extract_file".to_string());
                let phase = extracted
                    .optional_string(raw.error.phase)?
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| "extract".to_string());
                let message = extracted
                    .optional_string(raw.error.message)?
                    .or(extracted.optional_string(raw.error_msg)?)
                    .unwrap_or_else(|| {
                        "CBM extraction failed without an error message".to_string()
                    });
                let remediation = extracted
                    .optional_string(raw.error.remediation)?
                    .filter(|value| !value.is_empty())
                    .unwrap_or_else(|| {
                        "Inspect the exact extraction failure, fix the cause, then retry the "
                            .to_string()
                            + "complete corpus; partial extraction is forbidden."
                    });
                let path = extracted._rel_path.to_string_lossy();
                Err(envelope(
                    code,
                    format!(
                        "{message}; operation={operation}; phase={phase}; path={path}; requested={}",
                        raw.error.requested
                    ),
                    remediation,
                ))
            } else {
                Ok(extracted)
            }
        }
    }

    pub fn definitions(&self) -> Result<Vec<Definition>, BridgeError> {
        // SAFETY: self owns a live CBMFileResult until Drop; array pointers are CBM-owned.
        unsafe {
            array_slice(self.raw().defs.items, self.raw().defs.count, "defs")?
                .iter()
                .map(|item| self.definition(item))
                .collect()
        }
    }

    pub fn calls(&self) -> Result<Vec<Call>, BridgeError> {
        // SAFETY: self owns a live CBMFileResult until Drop; array pointers are CBM-owned.
        unsafe {
            array_slice(self.raw().calls.items, self.raw().calls.count, "calls")?
                .iter()
                .map(|item| self.call(item))
                .collect()
        }
    }

    pub fn imports(&self) -> Result<Vec<Import>, BridgeError> {
        // SAFETY: self owns a live CBMFileResult until Drop; array pointers are CBM-owned.
        unsafe {
            array_slice(
                self.raw().imports.items,
                self.raw().imports.count,
                "imports",
            )?
            .iter()
            .map(|item| {
                Ok(Import {
                    local_name: self.optional_string(item.local_name)?,
                    module_path: self.required_string(item.module_path, "import.module_path")?,
                    resource_kind: self.optional_string(item.resource_kind)?,
                    dependency_kind: self.optional_string(item.dependency_kind)?,
                    resolution: ImportResolution::try_from(item.resolution)?,
                    binding: ImportBinding::try_from(item.binding)?,
                })
            })
            .collect()
        }
    }

    pub fn usages(&self) -> Result<Vec<Usage>, BridgeError> {
        // SAFETY: self owns a live CBMFileResult until Drop; array pointers are CBM-owned.
        unsafe {
            array_slice(self.raw().usages.items, self.raw().usages.count, "usages")?
                .iter()
                .map(|item| {
                    Ok(Usage {
                        ref_name: self.required_string(item.ref_name, "usage.ref_name")?,
                        enclosing_func_qn: self.optional_string(item.enclosing_func_qn)?,
                    })
                })
                .collect()
        }
    }

    pub fn read_writes(&self) -> Result<Vec<ReadWrite>, BridgeError> {
        // SAFETY: self owns a live CBMFileResult until Drop; array pointers are CBM-owned.
        unsafe {
            array_slice(self.raw().rw.items, self.raw().rw.count, "rw")?
                .iter()
                .map(|item| {
                    Ok(ReadWrite {
                        var_name: self.required_string(item.var_name, "rw.var_name")?,
                        enclosing_func_qn: self.optional_string(item.enclosing_func_qn)?,
                        is_write: item.is_write,
                    })
                })
                .collect()
        }
    }

    pub fn throws(&self) -> Result<Vec<Throw>, BridgeError> {
        // SAFETY: self owns a live CBMFileResult until Drop; array pointers are CBM-owned.
        unsafe {
            array_slice(self.raw().throws.items, self.raw().throws.count, "throws")?
                .iter()
                .map(|item| {
                    Ok(Throw {
                        exception_name: self
                            .required_string(item.exception_name, "throw.exception_name")?,
                        enclosing_func_qn: self.optional_string(item.enclosing_func_qn)?,
                    })
                })
                .collect()
        }
    }

    pub fn type_refs(&self) -> Result<Vec<TypeRef>, BridgeError> {
        // SAFETY: self owns a live CBMFileResult until Drop; array pointers are CBM-owned.
        unsafe {
            array_slice(
                self.raw().type_refs.items,
                self.raw().type_refs.count,
                "type_refs",
            )?
            .iter()
            .map(|item| {
                Ok(TypeRef {
                    type_name: self.required_string(item.type_name, "type_ref.type_name")?,
                    enclosing_func_qn: self.optional_string(item.enclosing_func_qn)?,
                })
            })
            .collect()
        }
    }

    pub fn channels(&self) -> Result<Vec<Channel>, BridgeError> {
        // SAFETY: self owns a live CBMFileResult until Drop; array pointers are CBM-owned.
        unsafe {
            array_slice(
                self.raw().channels.items,
                self.raw().channels.count,
                "channels",
            )?
            .iter()
            .map(|item| {
                Ok(Channel {
                    channel_name: self
                        .required_string(item.channel_name, "channel.channel_name")?,
                    transport: self.optional_string(item.transport)?,
                    enclosing_func_qn: self.optional_string(item.enclosing_func_qn)?,
                    direction: item.direction,
                })
            })
            .collect()
        }
    }

    pub fn diagnostics(&self) -> Result<Vec<ParseDiagnostic>, BridgeError> {
        // SAFETY: self owns a live CBMFileResult until Drop; array/source pointers are
        // CBM-owned and remain valid for the duration of this copy.
        unsafe {
            array_slice(
                self.raw().diagnostics.items,
                self.raw().diagnostics.count,
                "diagnostics",
            )?
            .iter()
            .map(|item| {
                let source = if item.source_len == 0 {
                    Vec::new()
                } else {
                    if item.source.is_null() {
                        return Err(envelope(
                            "ASTRO_CBM_NULL_FIELD",
                            "CBM returned NULL for required field diagnostic.source",
                            "Treat this as FFI contract drift and keep the raw result for debugging.",
                        ));
                    }
                    std::slice::from_raw_parts(item.source.cast::<u8>(), item.source_len as usize)
                        .to_vec()
                };
                Ok(ParseDiagnostic {
                    code: self.required_string(item.code, "diagnostic.code")?,
                    operation: self.required_string(item.operation, "diagnostic.operation")?,
                    message: self.required_string(item.message, "diagnostic.message")?,
                    remediation: self
                        .required_string(item.remediation, "diagnostic.remediation")?,
                    node_type: self.required_string(item.node_type, "diagnostic.node_type")?,
                    start_line: item.start_line,
                    end_line: item.end_line,
                    start_byte: item.start_byte,
                    end_byte: item.end_byte,
                    source,
                    invalid_utf8_bytes: item.invalid_utf8_bytes,
                    quarantined_definitions: item.quarantined_definitions,
                    is_missing: item.is_missing,
                })
            })
            .collect()
        }
    }

    pub fn routes(&self) -> Result<Vec<Route>, BridgeError> {
        Ok(self
            .definitions()?
            .into_iter()
            .filter_map(|def| {
                let path = def.route_path?;
                Some(Route {
                    owner_qualified_name: def.qualified_name,
                    path,
                    method: def.route_method,
                })
            })
            .collect())
    }

    pub fn module_qn(&self) -> Result<Option<String>, BridgeError> {
        self.optional_string(self.raw().module_qn)
    }

    pub fn is_test_file(&self) -> bool {
        self.raw().is_test_file
    }

    fn raw(&self) -> &cbm_sys::CBMFileResult {
        // SAFETY: ptr is non-null and owned by self until Drop.
        unsafe { self.ptr.as_ref() }
    }

    fn definition(&self, item: &cbm_sys::CBMDefinition) -> Result<Definition, BridgeError> {
        Ok(Definition {
            name: self.required_string(item.name, "definition.name")?,
            qualified_name: self
                .required_string(item.qualified_name, "definition.qualified_name")?,
            label: self.required_string(item.label, "definition.label")?,
            file_path: self.optional_string(item.file_path)?,
            start_line: item.start_line,
            end_line: item.end_line,
            signature: self.optional_string(item.signature)?,
            return_type: self.optional_string(item.return_type)?,
            receiver: self.optional_string(item.receiver)?,
            docstring: self.optional_string(item.docstring)?,
            parent_class: self.optional_string(item.parent_class)?,
            route_path: self.optional_string(item.route_path)?,
            route_method: self.optional_string(item.route_method)?,
            complexity: item.complexity,
            cognitive: item.cognitive,
            loop_count: item.loop_count,
            loop_depth: item.loop_depth,
            is_recursive: item.is_recursive,
            param_count: item.param_count,
            max_access_depth: item.max_access_depth,
            linear_scan_in_loop: item.linear_scan_in_loop,
            alloc_in_loop: item.alloc_in_loop,
            recursion_in_loop: item.recursion_in_loop,
            unguarded_recursion: item.unguarded_recursion,
            lines: item.lines,
            fingerprint: self.fingerprint(item.fingerprint, item.fingerprint_k)?,
            is_exported: item.is_exported,
            is_abstract: item.is_abstract,
            is_test: item.is_test,
            is_entry_point: item.is_entry_point,
            structural_profile: self.optional_string(item.structural_profile)?,
            body_tokens: self.optional_string(item.body_tokens)?,
            struct_trigrams: self.optional_string(item.struct_trigrams)?,
        })
    }

    fn call(&self, item: &cbm_sys::CBMCall) -> Result<Call, BridgeError> {
        let arg_count = usize::try_from(item.arg_count)
            .map_err(|_| internal(format!("negative call argument count {}", item.arg_count)))?;
        if arg_count > item.args.len() {
            return Err(internal(format!(
                "call argument count {} exceeds fixed CBM_MAX_CALL_ARGS",
                item.arg_count
            )));
        }

        let mut args = Vec::with_capacity(arg_count);
        for arg in item.args.iter().take(arg_count) {
            args.push(CallArg {
                expr: self.optional_string(arg.expr)?,
                value: self.optional_string(arg.value)?,
                keyword: self.optional_string(arg.keyword)?,
                index: arg.index,
            });
        }

        Ok(Call {
            callee_name: self.required_string(item.callee_name, "call.callee_name")?,
            enclosing_func_qn: self.optional_string(item.enclosing_func_qn)?,
            first_string_arg: self.optional_string(item.first_string_arg)?,
            second_arg_name: self.optional_string(item.second_arg_name)?,
            args,
            loop_depth: item.loop_depth,
            branch_depth: item.branch_depth,
            start_line: item.start_line,
            is_method: item.is_method,
        })
    }

    fn fingerprint(&self, ptr: *mut u32, count: c_int) -> Result<Vec<u32>, BridgeError> {
        if count < 0 {
            return Err(internal(format!("negative fingerprint count {count}")));
        }
        if count == 0 {
            return Ok(Vec::new());
        }
        if ptr.is_null() {
            return Err(internal(
                "fingerprint count was positive but pointer was NULL",
            ));
        }
        // SAFETY: CBM owns `count` u32 values for the result lifetime.
        let slice = unsafe { std::slice::from_raw_parts(ptr, count as usize) };
        Ok(slice.to_vec())
    }

    fn required_string(&self, ptr: *const c_char, field: &str) -> Result<String, BridgeError> {
        self.optional_string(ptr)?.ok_or_else(|| {
            envelope(
                "ASTRO_CBM_NULL_FIELD",
                format!("CBM returned NULL for required field {field}"),
                "Treat this as FFI contract drift and keep the raw result for debugging.",
            )
        })
    }

    fn optional_string(&self, ptr: *const c_char) -> Result<Option<String>, BridgeError> {
        if ptr.is_null() {
            return Ok(None);
        }
        // SAFETY: CBM returns NUL-terminated strings owned by the result arena.
        let s = unsafe { CStr::from_ptr(ptr) }.to_str()?.to_owned();
        Ok(Some(s))
    }
}

impl Drop for ExtractedFile {
    fn drop(&mut self) {
        // SAFETY: self uniquely owns the CBMFileResult pointer.
        unsafe {
            cbm_sys::cbm_free_result(self.ptr.as_ptr());
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Definition {
    pub name: String,
    pub qualified_name: String,
    pub label: String,
    pub file_path: Option<String>,
    pub start_line: u32,
    pub end_line: u32,
    pub signature: Option<String>,
    pub return_type: Option<String>,
    pub receiver: Option<String>,
    pub docstring: Option<String>,
    pub parent_class: Option<String>,
    pub route_path: Option<String>,
    pub route_method: Option<String>,
    pub complexity: c_int,
    pub cognitive: c_int,
    pub loop_count: c_int,
    pub loop_depth: c_int,
    pub is_recursive: bool,
    pub param_count: c_int,
    pub max_access_depth: c_int,
    pub linear_scan_in_loop: c_int,
    pub alloc_in_loop: c_int,
    pub recursion_in_loop: bool,
    pub unguarded_recursion: bool,
    pub lines: c_int,
    pub fingerprint: Vec<u32>,
    pub is_exported: bool,
    pub is_abstract: bool,
    pub is_test: bool,
    pub is_entry_point: bool,
    pub structural_profile: Option<String>,
    pub body_tokens: Option<String>,
    /// Panel S1 encoder source: newline-delimited `a\tb\tc\tweight` records of
    /// normalised AST node-type struct trigrams (see [`Definition::parsed_struct_trigrams`]).
    pub struct_trigrams: Option<String>,
}

impl Definition {
    /// Parse the serialized [`Definition::struct_trigrams`] into `(a, b, c, weight)`
    /// tuples in document order. A malformed record fails closed with a coded error;
    /// the caller decides whether an empty list is a measurable structural surface.
    pub fn parsed_struct_trigrams(
        &self,
    ) -> Result<Vec<(String, String, String, f32)>, BridgeError> {
        let Some(raw) = self.struct_trigrams.as_deref() else {
            return Ok(Vec::new());
        };
        let mut out = Vec::new();
        for line in raw.split('\n') {
            if line.is_empty() {
                continue;
            }
            let mut fields = line.split('\t');
            let (Some(a), Some(b), Some(c), Some(w), None) = (
                fields.next(),
                fields.next(),
                fields.next(),
                fields.next(),
                fields.next(),
            ) else {
                return Err(envelope(
                    "ASTRO_CBM_STRUCT_TRIGRAM_MALFORMED",
                    format!(
                        "struct-trigram record `{line}` is not a 4-field a\\tb\\tc\\tweight tuple"
                    ),
                    "Treat this as libcbm serialization drift and reject the reparse as a fault.",
                ));
            };
            let weight: f32 = w.parse().map_err(|_| {
                envelope(
                    "ASTRO_CBM_STRUCT_TRIGRAM_MALFORMED",
                    format!("struct-trigram weight `{w}` in `{line}` is not a number"),
                    "Treat this as libcbm serialization drift and reject the reparse as a fault.",
                )
            })?;
            out.push((a.to_string(), b.to_string(), c.to_string(), weight));
        }
        Ok(out)
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CallArg {
    pub expr: Option<String>,
    pub value: Option<String>,
    pub keyword: Option<String>,
    pub index: c_int,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Call {
    pub callee_name: String,
    pub enclosing_func_qn: Option<String>,
    pub first_string_arg: Option<String>,
    pub second_arg_name: Option<String>,
    pub args: Vec<CallArg>,
    pub loop_depth: c_int,
    pub branch_depth: c_int,
    pub start_line: c_int,
    pub is_method: bool,
}

/// Source-resolution semantics retained byte-for-byte from libcbm extraction.
///
/// Historical dependency planning must distinguish an exact repository source
/// assertion from a semantic package/module name. Collapsing both to a string
/// either invents local files for external packages or misses required source
/// context in a file-scoped historical view.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ImportResolution {
    Semantic,
    ExactSource,
    ExternalSource,
    EsSource,
    BrowserUrl,
    RustModule,
}

impl TryFrom<cbm_sys::CBMImportResolution> for ImportResolution {
    type Error = BridgeError;

    fn try_from(value: cbm_sys::CBMImportResolution) -> Result<Self, Self::Error> {
        match value {
            cbm_sys::CBMImportResolution_CBM_IMPORT_RESOLVE_SEMANTIC => Ok(Self::Semantic),
            cbm_sys::CBMImportResolution_CBM_IMPORT_RESOLVE_EXACT_SOURCE => Ok(Self::ExactSource),
            cbm_sys::CBMImportResolution_CBM_IMPORT_RESOLVE_EXTERNAL_SOURCE => {
                Ok(Self::ExternalSource)
            }
            cbm_sys::CBMImportResolution_CBM_IMPORT_RESOLVE_ES_SOURCE => Ok(Self::EsSource),
            cbm_sys::CBMImportResolution_CBM_IMPORT_RESOLVE_BROWSER_URL => Ok(Self::BrowserUrl),
            cbm_sys::CBMImportResolution_CBM_IMPORT_RESOLVE_RUST_MODULE => Ok(Self::RustModule),
            other => Err(envelope(
                "ASTRO_CBM_IMPORT_RESOLUTION_INVALID",
                format!("libcbm returned unknown import resolution value {other}"),
                "Keep the Rust bridge enum synchronized with CBMImportResolution before consuming the extraction result.",
            )),
        }
    }
}

/// Whether an import binds a lexical name, records a resource relationship, or
/// represents an unbound source dependency such as PowerShell dot-sourcing.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum ImportBinding {
    Local,
    Resource,
    Unbound,
}

impl TryFrom<cbm_sys::CBMImportBinding> for ImportBinding {
    type Error = BridgeError;

    fn try_from(value: cbm_sys::CBMImportBinding) -> Result<Self, Self::Error> {
        match value {
            cbm_sys::CBMImportBinding_CBM_IMPORT_BINDING_LOCAL => Ok(Self::Local),
            cbm_sys::CBMImportBinding_CBM_IMPORT_BINDING_RESOURCE => Ok(Self::Resource),
            cbm_sys::CBMImportBinding_CBM_IMPORT_BINDING_UNBOUND => Ok(Self::Unbound),
            other => Err(envelope(
                "ASTRO_CBM_IMPORT_BINDING_INVALID",
                format!("libcbm returned unknown import binding value {other}"),
                "Keep the Rust bridge enum synchronized with CBMImportBinding before consuming the extraction result.",
            )),
        }
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Import {
    pub local_name: Option<String>,
    pub module_path: String,
    pub resource_kind: Option<String>,
    pub dependency_kind: Option<String>,
    pub resolution: ImportResolution,
    pub binding: ImportBinding,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Usage {
    pub ref_name: String,
    pub enclosing_func_qn: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ReadWrite {
    pub var_name: String,
    pub enclosing_func_qn: Option<String>,
    pub is_write: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Throw {
    pub exception_name: String,
    pub enclosing_func_qn: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct TypeRef {
    pub type_name: String,
    pub enclosing_func_qn: Option<String>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Channel {
    pub channel_name: String,
    pub transport: Option<String>,
    pub enclosing_func_qn: Option<String>,
    pub direction: cbm_sys::CBMChannelDirection,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ParseDiagnostic {
    pub code: String,
    pub operation: String,
    pub message: String,
    pub remediation: String,
    pub node_type: String,
    pub start_line: u32,
    pub end_line: u32,
    pub start_byte: u32,
    pub end_byte: u32,
    pub source: Vec<u8>,
    pub invalid_utf8_bytes: u32,
    pub quarantined_definitions: u32,
    pub is_missing: bool,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Route {
    pub owner_qualified_name: String,
    pub path: String,
    pub method: Option<String>,
}

struct CbmStore {
    ptr: NonNull<cbm_sys::cbm_store_t>,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CbmStoreNormalization {
    pub journal_mode_before: String,
    pub journal_mode_after: String,
    pub sqlite_error: i32,
    pub wal_log_frames: i32,
    pub wal_checkpointed_frames: i32,
    pub wal_remaining_frames: i32,
    pub operation: String,
    pub detail: String,
    pub sqlite_owned_empty_wal_created: bool,
    pub close_connection_destroyed: bool,
    pub close_db_path: String,
}

fn fixed_c_string<const N: usize>(value: &[c_char; N]) -> String {
    // Native fixed-width records are zero-initialized and all writes use
    // bounded snprintf/memcpy with a retained terminator.
    unsafe { CStr::from_ptr(value.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

fn store_close_bridge_error(
    code: &'static str,
    result: &cbm_sys::cbm_store_close_result_t,
) -> BridgeError {
    envelope(
        code,
        format!(
            "exact SQLite close failed (status={}, sqlite_error={}, connection_was_present={}, close_attempted={}, connection_destroyed={}, outstanding_statements={}, first_sql_sha256={:?}, first_sql={:?}, db_path={:?})",
            result.status,
            result.sqlite_close_code,
            result.connection_was_present,
            result.close_attempted,
            result.connection_destroyed,
            result.outstanding_statement_count,
            fixed_c_string(&result.first_outstanding_sql_sha256),
            fixed_c_string(&result.first_outstanding_sql),
            fixed_c_string(&result.db_path),
        ),
        "Preserve the exact store owner and database family; finalize the reported SQLite resource before retrying.",
    )
}

unsafe fn close_transient_store_or_abort(
    store: &mut *mut cbm_sys::cbm_store_t,
    operation: &str,
) -> cbm_sys::cbm_store_close_result_t {
    let mut result = cbm_sys::cbm_store_close_result_t::default();
    let _status = unsafe { cbm_sys::cbm_store_close(store, &mut result) };
    if result.connection_destroyed != 0 && (*store).is_null() {
        return result;
    }
    eprintln!(
        "code=ASTRO_CBM_TRANSIENT_STORE_CLOSE_FAILED operation={operation:?} status={} sqlite_error={} connection_destroyed={} outstanding_statements={} first_sql_sha256={:?} db_path={:?}",
        result.status,
        result.sqlite_close_code,
        result.connection_destroyed,
        result.outstanding_statement_count,
        fixed_c_string(&result.first_outstanding_sql_sha256),
        fixed_c_string(&result.db_path),
    );
    std::process::abort();
}

pub fn normalize_existing_project_store(
    db_path: &str,
    project: &str,
) -> Result<CbmStoreNormalization, BridgeError> {
    initialize_cbm_allocator()?;
    validate_project_name(project)?;
    let db_path = CString::new(db_path)?;
    let project = CString::new(project)?;
    let mut preflight = cbm_sys::cbm_store_verify_result_t::default();
    // SAFETY: both C strings and the fixed-width output remain live. The native
    // preflight verifies a frozen scratch DB/WAL family and never opens the live
    // source, so malformed bytes cannot create or mutate source sidecars.
    let preflight_status = unsafe {
        cbm_sys::cbm_store_verify_path_project_snapshot_for_normalization(
            db_path.as_ptr(),
            project.as_ptr(),
            &mut preflight,
        )
    };
    if preflight_status != cbm_sys::cbm_store_verify_status_t_CBM_STORE_VERIFY_OK {
        return Err(envelope(
            "ASTRO_CBM_NORMALIZE_PREFLIGHT_FAILED",
            format!(
                "frozen DB/WAL normalization preflight failed without opening the live source (status={preflight_status}, native_error={}, sqlite_error={}, operation={:?}, detail={:?}, db_path={:?}, project={:?})",
                preflight.native_error,
                preflight.sqlite_error,
                fixed_c_string(&preflight.operation),
                fixed_c_string(&preflight.detail),
                db_path.to_string_lossy(),
                project.to_string_lossy(),
            ),
            "Preserve the exact database family and repair the frozen source corruption before normalization.",
        ));
    }
    let mut store = ptr::null_mut();
    let mut verification = cbm_sys::cbm_store_verify_result_t::default();
    // SAFETY: both C strings and outputs remain live for the call. Any retained
    // owner is consumed below by the exact close boundary.
    let verify_status = unsafe {
        cbm_sys::cbm_store_open_path_project_writer_existing_bound(
            db_path.as_ptr(),
            project.as_ptr(),
            &preflight,
            &mut store,
            &mut verification,
        )
    };
    if verify_status != cbm_sys::cbm_store_verify_status_t_CBM_STORE_VERIFY_OK || store.is_null() {
        if !store.is_null() {
            // SAFETY: store is the exact retained owner returned above.
            let _ = unsafe {
                close_transient_store_or_abort(
                    &mut store,
                    "normalize_existing_project_store.open_failure",
                )
            };
        }
        return Err(envelope(
            "ASTRO_CBM_NORMALIZE_STORE_OPEN_FAILED",
            format!(
                "existing project writer verification failed (status={verify_status}, native_error={}, sqlite_error={}, operation={:?}, detail={:?}, db_path={:?}, project={:?})",
                verification.native_error,
                verification.sqlite_error,
                fixed_c_string(&verification.operation),
                fixed_c_string(&verification.detail),
                db_path.to_string_lossy(),
                project.to_string_lossy(),
            ),
            "Preserve the complete database family and resolve the exact writer-verification failure before normalization.",
        ));
    }

    let mut normalization = cbm_sys::cbm_store_normalize_result_t::default();
    // SAFETY: store is the unique verified writer and normalization is a live
    // fixed-width output record.
    let normalize_status =
        unsafe { cbm_sys::cbm_store_normalize_journal_mode_delete(store, &mut normalization) };
    // SAFETY: store is still the exact unique owner. Close is independent from
    // normalization and aborts rather than discarding a retained connection.
    let close = unsafe {
        close_transient_store_or_abort(&mut store, "normalize_existing_project_store.complete")
    };
    if normalize_status != cbm_sys::CBM_STORE_NORMALIZE_OK {
        return Err(envelope(
            "ASTRO_CBM_STORE_NORMALIZATION_FAILED",
            format!(
                "SQLite-owned journal normalization failed (status={}, sqlite_error={}, before={:?}, after={:?}, log_frames={}, checkpointed_frames={}, remaining_frames={}, operation={:?}, detail={:?}, close_connection_destroyed={})",
                normalization.status,
                normalization.sqlite_error,
                fixed_c_string(&normalization.journal_mode_before),
                fixed_c_string(&normalization.journal_mode_after),
                normalization.wal_log_frames,
                normalization.wal_checkpointed_frames,
                normalization.wal_remaining_frames,
                fixed_c_string(&normalization.operation),
                fixed_c_string(&normalization.detail),
                close.connection_destroyed,
            ),
            "Preserve the complete database family; resolve the checkpoint or journal-mode diagnostic before retrying.",
        ));
    }
    if close.status != cbm_sys::CBM_STORE_CLOSE_OK {
        return Err(store_close_bridge_error(
            "ASTRO_CBM_NORMALIZE_STORE_CLOSE_FAILED",
            &close,
        ));
    }

    Ok(CbmStoreNormalization {
        journal_mode_before: fixed_c_string(&normalization.journal_mode_before),
        journal_mode_after: fixed_c_string(&normalization.journal_mode_after),
        sqlite_error: normalization.sqlite_error,
        wal_log_frames: normalization.wal_log_frames,
        wal_checkpointed_frames: normalization.wal_checkpointed_frames,
        wal_remaining_frames: normalization.wal_remaining_frames,
        operation: fixed_c_string(&normalization.operation),
        detail: fixed_c_string(&normalization.detail),
        sqlite_owned_empty_wal_created: verification.sqlite_owned_empty_wal_created,
        close_connection_destroyed: close.connection_destroyed != 0,
        close_db_path: fixed_c_string(&close.db_path),
    })
}

impl CbmStore {
    fn open_memory() -> Result<Self, BridgeError> {
        initialize_cbm_allocator()?;
        // SAFETY: cbm_store_open_memory takes no borrowed inputs and returns
        // an owned store handle or NULL on allocation/open failure.
        let ptr = unsafe { cbm_sys::cbm_store_open_memory() };
        Ok(Self {
            ptr: NonNull::new(ptr).ok_or_else(|| {
                envelope(
                    "ASTRO_CBM_STORE_INIT",
                    "cbm_store_open_memory returned NULL",
                    "Check CBM allocator initialization and startup diagnostics.",
                )
            })?,
            _not_send_or_sync: PhantomData,
        })
    }
}

impl Drop for CbmStore {
    fn drop(&mut self) {
        let mut ptr = self.ptr.as_ptr();
        // SAFETY: self uniquely owns the cbm_store_t pointer. This legacy RAII
        // owner has no Result channel, so native required-close terminates on a
        // physical close failure instead of discarding the pointer.
        unsafe {
            cbm_sys::cbm_store_close_required(&mut ptr, c"bridge.CbmStore.drop".as_ptr());
        }
    }
}

type WatchCallback = dyn FnMut(&str, &str, &str) -> Result<(), BridgeError>;

const CBM_WATCHER_SOURCE_CHANGED: &str = "CBM_WATCHER_SOURCE_CHANGED";
const CBM_WATCHER_SOURCE_OBSERVATION_RECOVERED: &str = "CBM_WATCHER_SOURCE_OBSERVATION_RECOVERED";
const CBM_WATCHER_FAILURE_TRIGGERS: &[&str] = &[
    "CBM_WATCHER_GIT_CONTEXT_FAILED",
    "CBM_WATCHER_GIT_STATUS_FAILED",
    "CBM_WATCHER_GIT_IDENTITY_INVALID",
    "CBM_WATCHER_UNTRACKED_ALLOC_FAILED",
    "CBM_WATCHER_UNTRACKED_READ_FAILED",
    "CBM_WATCHER_GIT_DIFF_FAILED",
];

fn valid_watcher_trigger(trigger_code: &str) -> bool {
    trigger_code == CBM_WATCHER_SOURCE_CHANGED
        || trigger_code == CBM_WATCHER_SOURCE_OBSERVATION_RECOVERED
        || CBM_WATCHER_FAILURE_TRIGGERS.contains(&trigger_code)
}

struct WatcherCallbackState {
    callback: Box<WatchCallback>,
    last_error: Option<BridgeError>,
}

struct WatcherCallbackOwner {
    ptr: NonNull<WatcherCallbackState>,
}

impl WatcherCallbackOwner {
    fn new(callback: Box<WatchCallback>) -> Self {
        let state = Box::new(WatcherCallbackState {
            callback,
            last_error: None,
        });
        // Box::into_raw transfers the allocation into this owner without
        // creating a Box-derived reference that can be invalidated by moves.
        let ptr = NonNull::new(Box::into_raw(state)).expect("Box::into_raw returned NULL");
        Self { ptr }
    }

    fn user_data(&self) -> *mut c_void {
        self.ptr.as_ptr().cast::<c_void>()
    }

    fn clear_last_error(&mut self) {
        // SAFETY: this owner uniquely owns the allocation, and no C callback is
        // active while poll_once prepares the state.
        drop(unsafe { replace_watcher_last_error(self.ptr.as_ptr(), None) });
    }

    fn take_last_error(&mut self) -> Option<BridgeError> {
        // SAFETY: cbm_watcher_poll_once has returned, so no C callback is active.
        unsafe { replace_watcher_last_error(self.ptr.as_ptr(), None) }
    }
}

impl Drop for WatcherCallbackOwner {
    fn drop(&mut self) {
        // SAFETY: ptr came from exactly one Box::into_raw call and this owner is
        // its only reclamation path.
        unsafe {
            drop(Box::from_raw(self.ptr.as_ptr()));
        }
    }
}

pub struct CbmWatcher {
    ptr: NonNull<cbm_sys::cbm_watcher_t>,
    callback_state: WatcherCallbackOwner,
    _store: CbmStore,
    owner: ThreadId,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl CbmWatcher {
    pub fn new_for_polling<F>(callback: F) -> Result<Self, BridgeError>
    where
        F: FnMut(&str, &str, &str) -> Result<(), BridgeError> + 'static,
    {
        let store = CbmStore::open_memory()?;
        let callback_state = WatcherCallbackOwner::new(Box::new(callback));
        let user_data = callback_state.user_data();
        // SAFETY: store is owned by the returned CbmWatcher and therefore
        // outlives the C watcher. callback_state owns a Box::into_raw allocation
        // at a stable address until after the C watcher is stopped and freed.
        let ptr = unsafe {
            cbm_sys::cbm_watcher_new(
                store.ptr.as_ptr(),
                Some(watcher_index_trampoline),
                user_data,
            )
        };
        Ok(Self {
            ptr: NonNull::new(ptr).ok_or_else(|| {
                envelope(
                    "ASTRO_CBM_WATCHER_INIT",
                    "cbm_watcher_new returned NULL",
                    "Check CBM allocator initialization and startup diagnostics.",
                )
            })?,
            callback_state,
            _store: store,
            owner: thread::current().id(),
            _not_send_or_sync: PhantomData,
        })
    }

    pub fn watch(&mut self, project_name: &str, root_path: &str) -> Result<(), BridgeError> {
        self.ensure_owner_thread()?;
        validate_project_name(project_name)?;
        validate_shell_arg(root_path)?;
        let project_name = CString::new(project_name)?;
        let root_path = CString::new(root_path)?;
        // SAFETY: watcher pointer is owned by self and thread-affine. C copies
        // project_name and root_path during the call.
        unsafe {
            cbm_sys::cbm_watcher_watch(
                self.ptr.as_ptr(),
                project_name.as_ptr(),
                root_path.as_ptr(),
            );
        }
        Ok(())
    }

    pub fn unwatch(&mut self, project_name: &str) -> Result<(), BridgeError> {
        self.ensure_owner_thread()?;
        validate_project_name(project_name)?;
        let project_name = CString::new(project_name)?;
        // SAFETY: watcher pointer is owned by self and thread-affine. The C
        // string is live for the duration of the call.
        unsafe {
            cbm_sys::cbm_watcher_unwatch(self.ptr.as_ptr(), project_name.as_ptr());
        }
        Ok(())
    }

    pub fn touch(&mut self, project_name: &str) -> Result<(), BridgeError> {
        self.ensure_owner_thread()?;
        validate_project_name(project_name)?;
        let project_name = CString::new(project_name)?;
        // SAFETY: watcher pointer is owned by self and thread-affine. The C
        // string is live for the duration of the call.
        unsafe {
            cbm_sys::cbm_watcher_touch(self.ptr.as_ptr(), project_name.as_ptr());
        }
        Ok(())
    }

    pub fn invalidate(&mut self, project_name: &str) -> Result<(), BridgeError> {
        self.ensure_owner_thread()?;
        validate_project_name(project_name)?;
        let project_name = CString::new(project_name)?;
        // SAFETY: watcher pointer is owned by self and thread-affine. The C
        // string is live for the duration of the call.
        unsafe {
            cbm_sys::cbm_watcher_invalidate(self.ptr.as_ptr(), project_name.as_ptr());
        }
        Ok(())
    }

    pub fn poll_once(&mut self) -> Result<i32, BridgeError> {
        self.ensure_owner_thread()?;
        self.callback_state.clear_last_error();
        // SAFETY: watcher pointer is owned by self and thread-affine.
        let reindexed = unsafe { cbm_sys::cbm_watcher_poll_once(self.ptr.as_ptr()) };
        if let Some(err) = self.callback_state.take_last_error() {
            Err(err)
        } else {
            Ok(reindexed)
        }
    }

    pub fn watch_count(&self) -> Result<i32, BridgeError> {
        self.ensure_owner_thread()?;
        Ok(self.raw_watch_count())
    }

    pub fn poll_interval_ms(file_count: i32) -> i32 {
        // SAFETY: pure CBM helper with no pointer inputs.
        unsafe { cbm_sys::cbm_watcher_poll_interval_ms(file_count) }
    }

    fn raw_watch_count(&self) -> i32 {
        // SAFETY: watcher pointer is owned by self and thread-affine.
        unsafe { cbm_sys::cbm_watcher_watch_count(self.ptr.as_ptr()) }
    }

    fn ensure_owner_thread(&self) -> Result<(), BridgeError> {
        if thread::current().id() == self.owner {
            Ok(())
        } else {
            Err(envelope(
                "ASTRO_CBM_THREAD_AFFINITY",
                "CbmWatcher used from a different thread than the creating thread",
                "Create one CbmWatcher per thread; do not share cbm_watcher_t across threads.",
            ))
        }
    }
}

impl Drop for CbmWatcher {
    fn drop(&mut self) {
        // SAFETY: self uniquely owns the cbm_watcher_t pointer. The watcher is
        // not running on a background Rust thread in this wrapper. After this
        // method returns, callback_state reconstructs its Box before _store is
        // dropped, so C cannot retain or use user_data past reclamation.
        unsafe {
            cbm_sys::cbm_watcher_stop(self.ptr.as_ptr());
            cbm_sys::cbm_watcher_free(self.ptr.as_ptr());
        }
    }
}

unsafe fn replace_watcher_last_error(
    state: *mut WatcherCallbackState,
    replacement: Option<BridgeError>,
) -> Option<BridgeError> {
    // SAFETY: caller guarantees state points to the live Box::into_raw
    // allocation and that no competing callback access is active.
    unsafe { ptr::replace(ptr::addr_of_mut!((*state).last_error), replacement) }
}

unsafe extern "C" fn watcher_index_trampoline(
    project_name: *const c_char,
    root_path: *const c_char,
    trigger_code: *const c_char,
    user_data: *mut c_void,
) -> c_int {
    if user_data.is_null() {
        return CALLBACK_ERROR;
    }

    // user_data is the allocation pointer returned by Box::into_raw and remains
    // valid until after the C watcher is stopped and freed.
    let state = user_data.cast::<WatcherCallbackState>();
    match std::panic::catch_unwind(AssertUnwindSafe(|| {
        if project_name.is_null() || root_path.is_null() || trigger_code.is_null() {
            return Err(envelope(
                "ASTRO_CBM_NULL_CALLBACK_ARG",
                "CBM watcher callback received a NULL project name, root path, or trigger code",
                "Treat this as an FFI contract drift and inspect the watcher caller.",
            ));
        }
        // SAFETY: CBM calls the callback with NUL-terminated strings valid for
        // the duration of the callback.
        let project_name = unsafe { CStr::from_ptr(project_name) }.to_str()?;
        // SAFETY: same callback string contract as project_name.
        let root_path = unsafe { CStr::from_ptr(root_path) }.to_str()?;
        // SAFETY: same callback string contract as project_name.
        let trigger_code = unsafe { CStr::from_ptr(trigger_code) }.to_str()?;
        if !valid_watcher_trigger(trigger_code) {
            return Err(envelope(
                "ASTRO_CBM_WATCHER_TRIGGER_INVALID",
                format!("CBM watcher supplied unknown trigger code {trigger_code:?}"),
                "Regenerate the FFI binding and register the native trigger before consuming it.",
            ));
        }
        // SAFETY: C invokes this thread-affine callback synchronously, so this
        // is the only active access to the callback field.
        let callback = unsafe { &mut *ptr::addr_of_mut!((*state).callback) };
        callback(project_name, root_path, trigger_code)
    })) {
        Ok(Ok(())) => CALLBACK_OK,
        Ok(Err(err)) => {
            // SAFETY: state remains live and the callback borrow ended above.
            drop(unsafe { replace_watcher_last_error(state, Some(err)) });
            CALLBACK_ERROR
        }
        Err(_) => {
            // SAFETY: state remains live and catch_unwind ended callback access.
            drop(unsafe {
                replace_watcher_last_error(
                    state,
                    Some(envelope(
                        "ASTRO_FFI_CALLBACK_PANIC",
                        "Rust watcher callback panicked before returning to C",
                        "Keep panic boundaries inside Rust; convert watcher callback failures into status codes.",
                    )),
                )
            });
            CALLBACK_PANIC
        }
    }
}

fn validate_shell_arg(value: &str) -> Result<(), BridgeError> {
    let has_shell_metachar = value.chars().any(|ch| match ch {
        '\'' | '"' | ';' | '|' | '&' | '$' | '`' | '<' | '>' | '\n' | '\r' => true,
        #[cfg(not(windows))]
        '\\' => true,
        // cmd.exe expands %VAR% (and %X:~n,m% substring forms that can
        // materialize quotes) INSIDE double quotes at the CBM _popen sites,
        // and `^` escapes / `!VAR!` delayed expansion are the other documented
        // cmd.exe injection channels. POSIX shells treat these as literal
        // filename characters, so the rejection is Windows-only, mirroring the
        // `\\` platform split above. Audit #136.
        #[cfg(windows)]
        '%' | '^' | '!' => true,
        _ => false,
    });
    if has_shell_metachar {
        Err(envelope(
            "ASTRO_CBM_UNSAFE_SHELL_ARG",
            "watch root path contains a shell metacharacter rejected by CBM",
            "Pass a canonical repository path without quotes, shell operators, newlines, or cmd.exe expansion characters (% ^ !).",
        ))
    } else {
        Ok(())
    }
}

fn validate_project_name(value: &str) -> Result<(), BridgeError> {
    let valid = !value.is_empty()
        && !value.starts_with('.')
        && !value.contains("..")
        && !value.contains('/')
        && !value.contains('\\')
        && value
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.');
    if valid {
        Ok(())
    } else {
        Err(envelope(
            "ASTRO_CBM_INVALID_PROJECT_NAME",
            "project name is not safe for CBM cache path construction",
            "Use only ASCII letters, numbers, dash, underscore, and dot; do not use path separators or dot-dot.",
        ))
    }
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CbmProjectQuiescence {
    pub elapsed_ms: u64,
    pub attempts: u64,
    pub native_error: u64,
    pub failed_path: String,
    pub holder_probe_status: i32,
    pub holder_probe_native_error: u32,
    pub holder_inventory_stable: bool,
    pub holder_count: u64,
    pub first_holder_process_id: u32,
    pub first_holder_process_start_utc_ticks: u64,
    pub holder_probe_operation: String,
    pub first_holder_path: String,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CbmProjectQuiescenceError {
    pub error: BridgeError,
    pub evidence: Box<CbmProjectQuiescence>,
}

fn empty_project_quiescence() -> CbmProjectQuiescence {
    CbmProjectQuiescence {
        elapsed_ms: 0,
        attempts: 0,
        native_error: 0,
        failed_path: String::new(),
        holder_probe_status: cbm_sys::CBM_PROJECT_HOLDER_PROBE_NOT_RUN,
        holder_probe_native_error: 0,
        holder_inventory_stable: false,
        holder_count: 0,
        first_holder_process_id: 0,
        first_holder_process_start_utc_ticks: 0,
        holder_probe_operation: String::new(),
        first_holder_path: String::new(),
    }
}

pub struct CbmProjectTransition {
    ptr: Option<NonNull<cbm_sys::cbm_project_transition_t>>,
    owner: ThreadId,
    pub recovered_abandoned_owner: bool,
    pub owner_process_start_utc_ticks: u64,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl CbmProjectTransition {
    pub fn acquire(project: &str) -> Result<Self, BridgeError> {
        validate_project_name(project)?;
        let project = CString::new(project)?;
        let mut recovered_abandoned_owner = false;
        let mut owner_process_start_utc_ticks = 0;
        let mut native_error = 0;
        // SAFETY: all pointers refer to live, correctly sized values for the
        // duration of the call. The returned owner is released by this RAII type.
        let ptr = unsafe {
            cbm_sys::cbm_project_transition_acquire(
                project.as_ptr(),
                &mut recovered_abandoned_owner,
                &mut owner_process_start_utc_ticks,
                &mut native_error,
            )
        };
        Ok(Self {
            ptr: Some(NonNull::new(ptr).ok_or_else(|| {
                envelope(
                    "ASTRO_PROJECT_TRANSITION_ACQUIRE_FAILED",
                    format!(
                        "the exact project transition could not be acquired (native_error={native_error})"
                    ),
                    "If native_error is ERROR_BUSY, let the reported generation finish; otherwise resolve the Windows named-mutex failure before retrying.",
                )
            })?),
            owner: thread::current().id(),
            recovered_abandoned_owner,
            owner_process_start_utc_ticks,
            _not_send_or_sync: PhantomData,
        })
    }

    pub fn wait_store_quiescent(
        &self,
        db_path: &str,
        timeout_ms: u32,
        poll_ms: u32,
    ) -> Result<CbmProjectQuiescence, CbmProjectQuiescenceError> {
        self.ensure_owner_thread()
            .map_err(|error| CbmProjectQuiescenceError {
                error,
                evidence: Box::new(empty_project_quiescence()),
            })?;
        let db_path = CString::new(db_path).map_err(|error| CbmProjectQuiescenceError {
            error: error.into(),
            evidence: Box::new(empty_project_quiescence()),
        })?;
        // SAFETY: the bindgen record is a plain C POD initialized to zero.
        let mut report: cbm_sys::cbm_project_quiescence_result_t = unsafe { std::mem::zeroed() };
        // SAFETY: the transition remains owned by self, the C string and report
        // are live for the call, and this is the acquiring thread.
        let status = unsafe {
            cbm_sys::cbm_project_transition_wait_store_quiescent(
                self.ptr.expect("live project transition").as_ptr(),
                db_path.as_ptr(),
                timeout_ms,
                poll_ms,
                &mut report,
            )
        };
        // SAFETY: native initialization zeroes the fixed buffer and all writes
        // are bounded snprintf calls, so it always contains a terminating NUL.
        let failed_path = unsafe { CStr::from_ptr(report.failed_path.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        let holder_probe_operation =
            unsafe { CStr::from_ptr(report.holder_probe_operation.as_ptr()) }
                .to_string_lossy()
                .into_owned();
        let first_holder_path = unsafe { CStr::from_ptr(report.first_holder_path.as_ptr()) }
            .to_string_lossy()
            .into_owned();
        let evidence = CbmProjectQuiescence {
            elapsed_ms: report.elapsed_ms,
            attempts: report.attempts,
            native_error: report.native_error as u64,
            failed_path,
            holder_probe_status: report.holder_probe_status,
            holder_probe_native_error: report.holder_probe_native_error,
            holder_inventory_stable: report.holder_inventory_stable != 0,
            holder_count: report.holder_count,
            first_holder_process_id: report.first_holder_process_id,
            first_holder_process_start_utc_ticks: report.first_holder_process_start_utc_ticks,
            holder_probe_operation,
            first_holder_path,
        };
        match status {
            0 => Ok(evidence),
            1 => Err(CbmProjectQuiescenceError {
                error: envelope(
                    "ASTRO_PROJECT_TRANSITION_QUIESCENCE_TIMEOUT",
                    format!(
                        "the canonical store family remained open after {} ms and {} exact probes (native_error={}, path={:?}, holder_probe_status={}, holder_probe_native_error={}, holder_count={}, first_holder_pid={}, first_holder_start_ticks={}, first_holder_path={:?})",
                        evidence.elapsed_ms,
                        evidence.attempts,
                        evidence.native_error,
                        evidence.failed_path,
                        evidence.holder_probe_status,
                        evidence.holder_probe_native_error,
                        evidence.holder_count,
                        evidence.first_holder_process_id,
                        evidence.first_holder_process_start_utc_ticks,
                        evidence.first_holder_path,
                    ),
                    "Identify the process retaining the exact DB/WAL/SHM handle; do not terminate it or mutate the family, then retry after cooperative quiescence works.",
                ),
                evidence: Box::new(evidence),
            }),
            other => Err(CbmProjectQuiescenceError {
                error: envelope(
                    "ASTRO_PROJECT_TRANSITION_QUIESCENCE_PROBE_FAILED",
                    format!(
                        "canonical store-family quiescence probe failed with status {other}, native_error={}, path={:?}, holder_probe_status={}, holder_probe_native_error={}, holder_probe_operation={:?}",
                        evidence.native_error,
                        evidence.failed_path,
                        evidence.holder_probe_status,
                        evidence.holder_probe_native_error,
                        evidence.holder_probe_operation,
                    ),
                    "Resolve the structured Windows file-open failure before retrying the unchanged transition.",
                ),
                evidence: Box::new(evidence),
            }),
        }
    }

    pub fn release(mut self) -> Result<(), BridgeError> {
        self.ensure_owner_thread()?;
        self.release_inner()
    }

    fn ensure_owner_thread(&self) -> Result<(), BridgeError> {
        if thread::current().id() == self.owner {
            Ok(())
        } else {
            Err(envelope(
                "ASTRO_PROJECT_TRANSITION_THREAD_AFFINITY",
                "project transition used from a different thread than its acquiring owner",
                "Acquire, quiesce, complete, and release the transition on one thread.",
            ))
        }
    }

    fn release_inner(&mut self) -> Result<(), BridgeError> {
        let Some(ptr) = self.ptr.take() else {
            return Ok(());
        };
        let mut native_error = 0;
        // SAFETY: ptr is the live C owner generation and is consumed exactly once.
        let status =
            unsafe { cbm_sys::cbm_project_transition_release(ptr.as_ptr(), &mut native_error) };
        if status == 0 {
            Ok(())
        } else {
            Err(envelope(
                "ASTRO_PROJECT_TRANSITION_RELEASE_FAILED",
                format!(
                    "the exact project transition could not be released (native_error={native_error})"
                ),
                "Inspect the owner thread and durable transition receipt before retrying.",
            ))
        }
    }
}

impl Drop for CbmProjectTransition {
    fn drop(&mut self) {
        if self.ptr.is_some() && self.release_inner().is_err() {
            eprintln!("code=ASTRO_PROJECT_TRANSITION_RELEASE_FAILED message=drop_release_failed");
        }
    }
}

pub struct CbmToolRunner {
    ptr: NonNull<cbm_sys::cbm_mcp_server_t>,
    owner: ThreadId,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl CbmToolRunner {
    pub fn new_default() -> Result<Self, BridgeError> {
        Self::from_store_path_ptr(ptr::null())
    }

    pub fn new(store_path: &str) -> Result<Self, BridgeError> {
        let store_path = CString::new(store_path)?;
        Self::from_store_path_ptr(store_path.as_ptr())
    }

    fn from_store_path_ptr(store_path: *const c_char) -> Result<Self, BridgeError> {
        initialize_cbm_allocator()?;
        // SAFETY: store_path is either NULL (CBM default store path) or a live
        // C string for the duration of the call.
        let ptr = unsafe { cbm_sys::cbm_mcp_server_new(store_path) };
        Ok(Self {
            ptr: NonNull::new(ptr).ok_or_else(|| {
                envelope(
                    "ASTRO_CBM_SERVER_INIT",
                    "cbm_mcp_server_new returned NULL",
                    "Check store path permissions and CBM startup diagnostics.",
                )
            })?,
            owner: thread::current().id(),
            _not_send_or_sync: PhantomData,
        })
    }

    pub fn handle_jsonrpc_raw(&self, request_json: &str) -> Result<Option<String>, BridgeError> {
        self.ensure_owner_thread()?;
        let request_json = CString::new(request_json)?;
        // SAFETY: server pointer is owned by self and thread-affine; request_json
        // is live for the call. NULL response means notification/no response.
        unsafe {
            let ptr = cbm_sys::cbm_mcp_server_handle(self.ptr.as_ptr(), request_json.as_ptr());
            take_optional_c_string(ptr)
        }
    }

    /// Return the complete immutable CBM tool registry as one JSON object.
    ///
    /// The Astrolabe host owns the public MCP roster: it composes this complete
    /// registry with its Rust-native definitions before serving `tools/list`.
    /// Calling the unpaginated registry export here prevents either registry
    /// from being stranded behind the other implementation's cursor boundary.
    /// Production N is 14 CBM definitions (measured 2026-08-13, #1110); this is
    /// O(N) over generation-immutable schema bytes and opens no project store.
    pub fn tool_definitions_raw(&self) -> Result<String, BridgeError> {
        self.ensure_owner_thread()?;
        // SAFETY: `cbm_mcp_tools_list` returns one allocator-owned,
        // NUL-terminated string. `take_c_string` copies and releases it through
        // the allocator selected inside libcbm.
        unsafe { take_c_string(cbm_sys::cbm_mcp_tools_list()) }
    }

    pub fn handle_tool_raw(&self, tool_name: &str, args_json: &str) -> Result<String, BridgeError> {
        self.ensure_owner_thread()?;
        let bound_args = if tool_name == "index_repository" {
            Some(bind_compilation_context_to_index_args(args_json)?)
        } else {
            None
        };
        let tool_name = CString::new(tool_name)?;
        let args_json = CString::new(bound_args.as_deref().unwrap_or(args_json))?;
        // SAFETY: server pointer is owned by self and thread-affine; C strings
        // outlive the call; the returned heap string is freed by CStringAllocation.
        unsafe {
            let ptr = cbm_sys::cbm_mcp_handle_tool(
                self.ptr.as_ptr(),
                tool_name.as_ptr(),
                args_json.as_ptr(),
            );
            take_c_string(ptr)
        }
    }

    /// Cooperatively closes this runner's exact cached project store when a
    /// different thread/process owns the root-derived Astrolabe publication
    /// transition. The C server remains thread-affine: resident dispatch calls
    /// this from the same owner thread between requests.
    pub fn quiesce_project_transition(&self) -> Result<bool, BridgeError> {
        self.ensure_owner_thread()?;
        // SAFETY: `self.ptr` is uniquely owned and this method is restricted to
        // the runner's owner thread. The native function performs no callbacks.
        let status =
            unsafe { cbm_sys::cbm_mcp_server_quiesce_project_transition(self.ptr.as_ptr()) };
        match status {
            0 => Ok(false),
            1 => Ok(true),
            other => Err(envelope(
                "ASTRO_CBM_PROJECT_TRANSITION_PROBE_FAILED",
                format!(
                    "native resident transition probe returned status {other}; inspect the native diagnostic for the exact cached-store disposition"
                ),
                "Resolve the structured native identity, named-mutex, or exact-close failure before reopening the project.",
            )),
        }
    }

    /// Close any named project store cached by this exact runner before its
    /// owner thread publishes a writer transition. A zero timeout is an exact
    /// eviction request; the initial anonymous in-memory store remains exempt.
    pub fn close_cached_project_store(&self) -> Result<(), BridgeError> {
        self.ensure_owner_thread()?;
        let mut result = cbm_sys::cbm_store_close_result_t::default();
        // SAFETY: `self.ptr` is uniquely owned and called on its owner thread;
        // result is a live, correctly sized fixed-width output record.
        let status = unsafe {
            cbm_sys::cbm_mcp_server_close_cached_project_store(self.ptr.as_ptr(), &mut result)
        };
        let exact_success = status == cbm_sys::CBM_STORE_CLOSE_OK
            && (result.connection_was_present == 0 || result.connection_destroyed != 0);
        if exact_success {
            return Ok(());
        }
        Err(store_close_bridge_error(
            "ASTRO_CBM_CACHED_STORE_CLOSE_FAILED",
            &result,
        ))
    }

    pub fn handle_index_repository_with_rows(
        &self,
        args_json: &str,
    ) -> Result<CbmIndexRepositoryRows, BridgeError> {
        self.ensure_owner_thread()?;
        let args_json = bind_compilation_context_to_index_args(args_json)?;
        let tool_name = CString::new("index_repository")?;
        let args_json = CString::new(args_json)?;
        let mut sink = PipelineRowSinkState::new();
        let descriptor = pipeline_row_sink_descriptor(&mut sink);

        // SAFETY: server pointer is owned by self and thread-affine. `sink`
        // lives until cbm_mcp_handle_tool returns and is cleared immediately.
        let raw_result = unsafe {
            map_cbm_status(cbm_sys::cbm_mcp_server_set_row_sink(
                self.ptr.as_ptr(),
                &descriptor,
            ))?;
            let ptr = cbm_sys::cbm_mcp_handle_tool(
                self.ptr.as_ptr(),
                tool_name.as_ptr(),
                args_json.as_ptr(),
            );
            map_cbm_status(cbm_sys::cbm_mcp_server_set_row_sink(
                self.ptr.as_ptr(),
                ptr::null(),
            ))?;
            take_c_string(ptr)
        };
        let raw_json = raw_result?;
        // #123: the index already ran to completion here — a row-sink failure is
        // returned ALONGSIDE the raw result rather than discarding it, so the
        // caller never has to rerun the whole index to recover the tool result.
        let project = project_from_tool_result(&raw_json)
            .or_else(|| {
                sink.manifest
                    .as_ref()
                    .map(|manifest| manifest.project.clone())
            })
            .or_else(|| sink.nodes.first().map(|node| node.project.clone()))
            .or_else(|| sink.edges.first().map(|edge| edge.project.clone()))
            .or_else(|| {
                sink.file_hashes
                    .first()
                    .map(|file_hash| file_hash.project.clone())
            })
            .unwrap_or_default();
        let rows = finish_pipeline_rows(sink, project);
        Ok(CbmIndexRepositoryRows { raw_json, rows })
    }

    /// Runs `index_repository` OUT OF PROCESS via the CBM supervisor, failing
    /// closed rather than degrading to the in-process pipeline (#405).
    ///
    /// This is the shadow full-index entry. It registers **no** row sink — an FFI
    /// callback cannot cross the supervisor's process boundary — so the CBM
    /// pipeline pass runs in a supervised child. A hard pass abort
    /// (segfault/abort-class) is therefore contained in the child; the parent
    /// rebuilds the graph row stream from the child's persisted `<project>.db`
    /// afterwards ([`astrolabe_ingest::read_cbm_sqlite_pipeline_rows`]) instead of
    /// from the row sink. On a clean child exit this returns the child's own
    /// `index_repository` response verbatim. A spawn failure, an unavailable
    /// supervisor, or a contained worker crash/hang is returned as a fail-closed
    /// `{isError}` tool result (carrying `outcome`, and in diagnostic builds the
    /// worker exit code and log tail) so the caller refuses before it touches the
    /// vault. Unlike the row-sink path this never runs the pipeline in-process.
    pub fn handle_index_repository_supervised(
        &self,
        args_json: &str,
    ) -> Result<String, BridgeError> {
        self.ensure_owner_thread()?;
        let args_json = bind_compilation_context_to_index_args(args_json)?;
        let args_json = CString::new(args_json)?;
        // SAFETY: server pointer is owned by self and thread-affine; args_json is
        // live for the call. The returned heap string is freed by take_c_string.
        unsafe {
            let ptr = cbm_sys::cbm_mcp_index_repository_supervised_strict(
                self.ptr.as_ptr(),
                args_json.as_ptr(),
            );
            take_c_string(ptr)
        }
    }

    pub fn handle_tool(
        &self,
        tool_name: &str,
        args_json: &str,
    ) -> Result<ToolResponse, BridgeError> {
        let raw = self.handle_tool_raw(tool_name, args_json)?;
        let value: serde_json::Value = serde_json::from_str(&raw).map_err(|err| {
            BridgeError::new(
                ErrorEnvelope::new(
                    "ASTRO_CBM_INTERNAL",
                    format!("CBM returned invalid JSON: {err}"),
                    "Capture the raw tool response and inspect CBM output formatting.",
                )
                .with_stderr(raw.clone()),
            )
        })?;
        if value
            .get("isError")
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false)
        {
            return Err(tool_error(&value, &raw));
        }
        Ok(ToolResponse {
            raw_json: raw,
            value,
        })
    }

    fn ensure_owner_thread(&self) -> Result<(), BridgeError> {
        if thread::current().id() == self.owner {
            Ok(())
        } else {
            Err(envelope(
                "ASTRO_CBM_THREAD_AFFINITY",
                "CbmToolRunner used from a different thread than the creating thread",
                "Create one CbmToolRunner per thread; do not share cbm_mcp_server_t across threads.",
            ))
        }
    }
}

impl Drop for CbmToolRunner {
    fn drop(&mut self) {
        // SAFETY: self uniquely owns the cbm_mcp_server_t pointer.
        unsafe {
            cbm_sys::cbm_mcp_server_free(self.ptr.as_ptr());
        }
    }
}

#[derive(Debug, Clone)]
pub struct ToolResponse {
    pub raw_json: String,
    pub value: serde_json::Value,
}

fn tool_error(value: &serde_json::Value, raw: &str) -> BridgeError {
    let message = value
        .get("content")
        .and_then(serde_json::Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("text"))
        .and_then(serde_json::Value::as_str)
        .unwrap_or("CBM tool returned isError=true");
    BridgeError::new(
        ErrorEnvelope::new(
            "ASTRO_CBM_TOOL_ERROR",
            message,
            "Inspect the tool arguments and retry with a valid indexed project/context.",
        )
        .with_stderr(raw.to_string()),
    )
}

fn project_from_tool_result(raw: &str) -> Option<String> {
    let value = serde_json::from_str::<serde_json::Value>(raw).ok()?;
    if let Some(project) = value
        .get("structuredContent")
        .and_then(|content| content.get("project"))
        .and_then(serde_json::Value::as_str)
    {
        return Some(project.to_string());
    }
    let text = value
        .get("content")
        .and_then(serde_json::Value::as_array)
        .and_then(|items| items.first())
        .and_then(|item| item.get("text"))
        .and_then(serde_json::Value::as_str)?;
    serde_json::from_str::<serde_json::Value>(text)
        .ok()?
        .get("project")
        .and_then(serde_json::Value::as_str)
        .map(ToOwned::to_owned)
}

struct CStringAllocation(NonNull<c_char>);

impl Drop for CStringAllocation {
    fn drop(&mut self) {
        // SAFETY: this pointer came from a CBM owned-string API and must be
        // released through the allocator selected inside libcbm.
        unsafe {
            cbm_sys::cbm_free_string(self.0.as_ptr());
        }
    }
}

unsafe fn take_c_string(ptr: *mut c_char) -> Result<String, BridgeError> {
    let allocation = CStringAllocation(NonNull::new(ptr).ok_or_else(|| {
        envelope(
            "ASTRO_CBM_NULL_RESULT",
            "CBM returned NULL for a heap string result",
            "Inspect CBM diagnostics; this is an FFI contract failure.",
        )
    })?);
    // SAFETY: allocation points at a NUL-terminated C string until Drop.
    let bytes = unsafe { CStr::from_ptr(allocation.0.as_ptr()) }
        .to_bytes()
        .to_vec();
    Ok(String::from_utf8(bytes)?)
}

unsafe fn take_optional_c_string(ptr: *mut c_char) -> Result<Option<String>, BridgeError> {
    if ptr.is_null() {
        return Ok(None);
    }
    // SAFETY: caller received this pointer from a CBM heap-string API.
    unsafe { take_c_string(ptr) }.map(Some)
}

unsafe fn array_slice<'a, T>(
    items: *mut T,
    count: c_int,
    label: &str,
) -> Result<&'a [T], BridgeError> {
    if count < 0 {
        return Err(internal(format!("negative {label} count {count}")));
    }
    if count == 0 {
        return Ok(&[]);
    }
    if items.is_null() {
        return Err(internal(format!(
            "{label} count was positive but pointer was NULL"
        )));
    }
    // SAFETY: caller ties the returned slice to a live CBMFileResult owner.
    Ok(unsafe { std::slice::from_raw_parts(items, count as usize) })
}
