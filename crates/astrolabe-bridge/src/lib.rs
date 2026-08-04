#![deny(unsafe_op_in_unsafe_fn)]

use std::collections::BTreeMap;
use std::convert::TryFrom;
use std::error::Error;
use std::ffi::{CStr, CString, NulError};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::marker::PhantomData;
use std::os::raw::{c_char, c_int, c_void};
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::ptr::{self, NonNull};
use std::rc::Rc;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::{self, ThreadId};

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

fn initialize_cbm_allocator() -> Result<(), BridgeError> {
    cbm_sys::initialize_allocator_bindings_first()
        .map_err(|error| envelope(error.code, error.message, error.remediation))
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

pub fn initialize_cbm_host_process(binary_path: Option<&str>) -> Result<(), BridgeError> {
    initialize_cbm_host_process_with_log_mode(binary_path, CbmLogMode::Default)
}

pub fn initialize_cbm_host_process_silent(binary_path: Option<&str>) -> Result<(), BridgeError> {
    initialize_cbm_host_process_with_log_mode(binary_path, CbmLogMode::Silent)
}

/// Initialize the CBM host process for a `cli <tool>` invocation, raising the
/// libcbm log floor to the registry-declared `cli_stderr_log_level_floor` (WARN)
/// so per-call INFO lines (`mem.init`/`vmem.init`) never reach stderr (#392).
/// Warnings and errors still flow through the tracing sink to stderr.
pub fn initialize_cbm_host_process_cli(binary_path: Option<&str>) -> Result<(), BridgeError> {
    initialize_cbm_host_process_with_log_mode(binary_path, CbmLogMode::CliWarnFloor)
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

fn initialize_cbm_host_process_with_log_mode(
    binary_path: Option<&str>,
    log_mode: CbmLogMode,
) -> Result<(), BridgeError> {
    initialize_cbm_log_configuration()?;
    // Refuse a store-relocating environment at startup rather than discovering it
    // one indexed project too late (#194/#232).
    validate_cbm_store_env(
        std::env::var("CBM_CACHE_DIR").ok().as_deref(),
        std::env::var("HOME").ok().as_deref(),
        std::env::var("USERPROFILE").ok().as_deref(),
    )?;
    initialize_cbm_allocator()?;
    let binary_path = binary_path.map(CString::new).transpose()?;

    let profile_active = initialize_cbm_profile_mode()?;
    // SAFETY: all called CBM startup functions are process-global initializers
    // intended for main() startup. The optional binary path C string is live for
    // the duration of the call; CBM copies it internally.
    unsafe {
        match log_mode {
            CbmLogMode::Default => {}
            CbmLogMode::CliWarnFloor => {
                // #392: reserve CLI stderr for warn/error. Raise the libcbm log
                // floor to the registry-declared ordinal (WARN) BEFORE cbm_mem_init
                // so its INFO `mem.init`/`vmem.init` lines are dropped at the
                // source rather than emitted. Warn/error still flow to stderr via
                // the tracing sink installed by route_cbm_logs_to_tracing().
                // Explicit profiling requests native INFO diagnostics, so it
                // keeps the level selected by cbm_log_init_from_env.
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
        cbm_sys::cbm_index_supervisor_mark_host();
        cbm_sys::cbm_cli_set_version(c"dev".as_ptr());

        let info = cbm_sys::cbm_system_info();
        let ram_fraction = cbm_sys::cbm_mem_ram_fraction_for_total(info.total_ram);
        cbm_sys::cbm_mem_init(ram_fraction);

        if let Some(binary_path) = binary_path.as_ref() {
            cbm_sys::cbm_http_server_set_binary_path(binary_path.as_ptr());
        }
    }

    Ok(())
}

unsafe extern "C" fn cbm_log_silent_sink(_line: *const c_char) {}

pub struct CbmIndexWorkerRole {
    _response_out: Option<CString>,
    _transition_writer_project: Option<CString>,
}

impl CbmIndexWorkerRole {
    pub fn activate(
        response_out: Option<&str>,
        transition_writer_project: Option<&str>,
    ) -> Result<Self, BridgeError> {
        initialize_cbm_allocator()?;
        let response_out = response_out.map(CString::new).transpose()?;
        let transition_writer_project = transition_writer_project.map(CString::new).transpose()?;
        // SAFETY: CBM copies response_out into process-global worker state.
        unsafe {
            cbm_sys::cbm_index_set_worker_role(
                true,
                response_out
                    .as_ref()
                    .map_or(ptr::null(), |path| path.as_ptr()),
            );
            cbm_sys::cbm_index_set_transition_writer_project(
                transition_writer_project
                    .as_ref()
                    .map_or(ptr::null(), |project| project.as_ptr()),
            );
        }
        Ok(Self {
            _response_out: response_out,
            _transition_writer_project: transition_writer_project,
        })
    }
}

impl Drop for CbmIndexWorkerRole {
    fn drop(&mut self) {
        // SAFETY: resetting the process-global worker role has no preconditions.
        unsafe {
            cbm_sys::cbm_index_set_transition_writer_project(ptr::null());
            cbm_sys::cbm_index_set_worker_role(false, ptr::null());
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
        self.edges.push(CbmPipelineEdgeRow {
            id: row.id,
            project: required_borrowed_c_string(row.project, "row_sink.edge.project")?,
            source_id: row.source_id,
            target_id: row.target_id,
            edge_type: required_borrowed_c_string(row.type_, "row_sink.edge.type")?,
            properties_json: required_borrowed_c_string(
                row.properties_json,
                "row_sink.edge.properties_json",
            )?,
            url_path_gen: required_borrowed_c_string(
                row.url_path_gen,
                "row_sink.edge.url_path_gen",
            )?,
            local_name_gen: required_borrowed_c_string(
                row.local_name_gen,
                "row_sink.edge.local_name_gen",
            )?,
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
) -> Result<Output, BridgeError> {
    let output = Command::new(&arguments[0])
        .args(&arguments[1..])
        .current_dir(directory)
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
    )?;
    let dependencies =
        parse_make_dependencies(&dependency_output.stdout, repo_root, &directory, &file_path)?;
    Ok(Some(RepositoryCompileCommand {
        file,
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
        if !baselines_empty || !commands_empty || value.get("capture").is_some() {
            return Err(envelope(
                "ASTRO_COMPILE_CONTEXT_ABSENCE_CONTRADICTORY",
                "absent compilation-context authority carries compiler state",
                "Preserve the contradictory manifest and regenerate it from one repository state.",
            ));
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
        validate_bound_compilation_context(&repo_path, context_json)?;
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
    validate_bound_compilation_context(&repo_path, &context_json)?;
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
) -> cbm_sys::cbm_pipeline_row_sink_v1_t {
    cbm_sys::cbm_pipeline_row_sink_v1_t {
        abi_version: cbm_sys::CBM_PIPELINE_ROW_SINK_ABI_V1,
        struct_size: std::mem::size_of::<cbm_sys::cbm_pipeline_row_sink_v1_t>(),
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
    pub fn extract(
        source: &str,
        language: Language,
        project: &str,
        rel_path: &str,
        timeout_micros: i64,
    ) -> Result<Self, BridgeError> {
        Self::extract_with_rust_context(source, language, project, rel_path, false, timeout_micros)
    }

    pub fn extract_with_rust_context(
        source: &str,
        language: Language,
        project: &str,
        rel_path: &str,
        rust_is_crate_root: bool,
        timeout_micros: i64,
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

        // SAFETY: cbm_init is idempotent in libcbm. The C strings outlive the call,
        // and source is passed with an explicit byte length.
        unsafe {
            map_cbm_status(cbm_sys::cbm_init())?;
            let ptr = cbm_sys::cbm_extract_file_at_path_with_rust_edition(
                source.as_ptr().cast::<c_char>(),
                source_len,
                language.as_raw(),
                project.as_ptr(),
                rel_path.as_ptr(),
                ptr::null(),
                ptr::null(),
                rust_is_crate_root,
                timeout_micros,
                ptr::null_mut(),
                ptr::null_mut(),
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

type WatchCallback = dyn FnMut(&str, &str) -> Result<(), BridgeError>;

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
        F: FnMut(&str, &str) -> Result<(), BridgeError> + 'static,
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

    pub fn root_missing_errno(errno: i32) -> bool {
        // SAFETY: pure CBM helper with no pointer inputs.
        unsafe { cbm_sys::cbm_watcher_root_missing_errno(errno) }
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
    user_data: *mut c_void,
) -> c_int {
    if user_data.is_null() {
        return CALLBACK_ERROR;
    }

    // user_data is the allocation pointer returned by Box::into_raw and remains
    // valid until after the C watcher is stopped and freed.
    let state = user_data.cast::<WatcherCallbackState>();
    match std::panic::catch_unwind(AssertUnwindSafe(|| {
        if project_name.is_null() || root_path.is_null() {
            return Err(envelope(
                "ASTRO_CBM_NULL_CALLBACK_ARG",
                "CBM watcher callback received a NULL project name or root path",
                "Treat this as an FFI contract drift and inspect the watcher caller.",
            ));
        }
        // SAFETY: CBM calls the callback with NUL-terminated strings valid for
        // the duration of the callback.
        let project_name = unsafe { CStr::from_ptr(project_name) }.to_str()?;
        // SAFETY: same callback string contract as project_name.
        let root_path = unsafe { CStr::from_ptr(root_path) }.to_str()?;
        // SAFETY: C invokes this thread-affine callback synchronously, so this
        // is the only active access to the callback field.
        let callback = unsafe { &mut *ptr::addr_of_mut!((*state).callback) };
        callback(project_name, root_path)
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
