#![deny(unsafe_op_in_unsafe_fn)]

use std::convert::TryFrom;
use std::error::Error;
use std::ffi::{CStr, CString, NulError};
use std::fmt;
use std::marker::PhantomData;
use std::os::raw::{c_char, c_int, c_void};
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::ptr::{self, NonNull};
use std::rc::Rc;
use std::thread::{self, ThreadId};

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");

pub fn parent_roots() -> (&'static str, &'static str) {
    (
        astrolabe_domain::calyx_vendor_root(),
        cbm_sys::vendor_root(),
    )
}

/// Byte capacity of a CBM store path.
///
/// `cbm_resolve_cache_dir` and `cbm_get_home_dir`
/// (`vendor/codebase-memory-mcp/src/foundation/platform.c`) publish their result
/// from a `static char[CBM_SZ_1K]`, so a store path longer than this cannot be
/// represented by the library at all. Astrolabe's store overlay
/// (`patches/cbm/env_apply_store_patch.py`, #241) widens the *environment* scratch
/// buffers those resolvers used — a `char[CBM_SZ_256]`, an artificial cut with no
/// relation to what the library can hold, and one that silently relocated the store
/// for any Windows path over 255 bytes — up to the same `CBM_SZ_1K`, and refuses
/// anything longer with a named fault instead of truncating it.
///
/// This is not a magic number: it is measured from the vendored
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
    cbm_sys::initialize_allocator_bindings_first();
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
    cbm_sys::initialize_allocator_bindings_first();
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

    cbm_sys::initialize_allocator_bindings_first();
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
pub fn clear_cbm_cache_dir() {
    cbm_sys::initialize_allocator_bindings_first();
    // SAFETY: process-global reset of libcbm's override buffer; no borrowed inputs.
    unsafe { cbm_sys::cbm_astro_clear_cache_dir() };
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

    cbm_sys::initialize_allocator_bindings_first();
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

pub fn cbm_memory_budget_bytes() -> usize {
    cbm_sys::initialize_allocator_bindings_first();
    // SAFETY: these CBM functions are process-global budget initializers/readers
    // with no borrowed inputs. cbm_mem_init is idempotent.
    unsafe {
        let info = cbm_sys::cbm_system_info();
        let ram_fraction = cbm_sys::cbm_mem_ram_fraction_for_total(info.total_ram);
        cbm_sys::cbm_mem_init(ram_fraction);
        cbm_sys::cbm_mem_budget()
    }
}

pub fn cbm_project_name_from_path(path: &str) -> Result<String, BridgeError> {
    cbm_sys::initialize_allocator_bindings_first();
    let path = CString::new(path)?;
    let ptr = unsafe { cbm_sys::cbm_project_name_from_path(path.as_ptr()) };
    unsafe { take_c_string(ptr) }
}

pub fn route_cbm_logs_to_tracing() {
    cbm_sys::initialize_allocator_bindings_first();
    // SAFETY: the callback is a static extern function and remains valid for
    // the process lifetime. CBM stores only the function pointer.
    unsafe {
        cbm_sys::cbm_log_init_from_env();
        cbm_sys::cbm_log_set_sink_ex(
            Some(cbm_log_tracing_sink),
            cbm_sys::CBMLogSinkMode_CBM_LOG_SINK_REPLACE,
        );
    }
}

pub fn initialize_cbm_host_process(binary_path: Option<&str>) -> Result<(), BridgeError> {
    initialize_cbm_host_process_with_log_mode(binary_path, false)
}

pub fn initialize_cbm_host_process_silent(binary_path: Option<&str>) -> Result<(), BridgeError> {
    initialize_cbm_host_process_with_log_mode(binary_path, true)
}

pub fn run_cbm_installer_command(command: &str, args: &[String]) -> Result<i32, BridgeError> {
    cbm_sys::initialize_allocator_bindings_first();
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
    cbm_sys::initialize_allocator_bindings_first();
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
    silent: bool,
) -> Result<(), BridgeError> {
    // Refuse a store-relocating environment at startup rather than discovering it
    // one indexed project too late (#194/#232).
    validate_cbm_store_env(
        std::env::var("CBM_CACHE_DIR").ok().as_deref(),
        std::env::var("HOME").ok().as_deref(),
        std::env::var("USERPROFILE").ok().as_deref(),
    )?;
    cbm_sys::initialize_allocator_bindings_first();
    let binary_path = binary_path.map(CString::new).transpose()?;

    // SAFETY: all called CBM startup functions are process-global initializers
    // intended for main() startup. The optional binary path C string is live for
    // the duration of the call; CBM copies it internally.
    unsafe {
        cbm_sys::cbm_log_init_from_env();
        if silent {
            cbm_sys::cbm_log_set_level(cbm_sys::CBMLogLevel_CBM_LOG_NONE);
            cbm_sys::cbm_log_set_sink_ex(
                Some(cbm_log_silent_sink),
                cbm_sys::CBMLogSinkMode_CBM_LOG_SINK_REPLACE,
            );
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
}

impl CbmIndexWorkerRole {
    pub fn activate(response_out: Option<&str>) -> Result<Self, BridgeError> {
        cbm_sys::initialize_allocator_bindings_first();
        let response_out = response_out.map(CString::new).transpose()?;
        // SAFETY: CBM copies response_out into process-global worker state.
        unsafe {
            cbm_sys::cbm_index_set_worker_role(
                true,
                response_out
                    .as_ref()
                    .map_or(ptr::null(), |path| path.as_ptr()),
            );
        }
        Ok(Self {
            _response_out: response_out,
        })
    }
}

impl Drop for CbmIndexWorkerRole {
    fn drop(&mut self) {
        // SAFETY: resetting the process-global worker role has no preconditions.
        unsafe {
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
        let line = unsafe { CStr::from_ptr(line) }.to_string_lossy();
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

#[cfg(not(any(unix, windows)))]
pub fn parent_process_id() -> Option<u32> {
    None
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

    const PROCESS_BASIC_INFORMATION_CLASS: i32 = 0;
    const SYNCHRONIZE: u32 = 0x0010_0000;
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
        write!(f, "{}: {}", self.envelope.code, self.envelope.message)
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

    pub fn from_raw(raw: cbm_sys::CBMLanguage) -> Self {
        Self(raw)
    }

    pub fn as_raw(self) -> cbm_sys::CBMLanguage {
        self.0
    }
}

pub fn map_cbm_status(status: i32) -> Result<(), BridgeError> {
    match status {
        0 => Ok(()),
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CbmPipelineNodeRow {
    pub id: i64,
    pub project: String,
    pub label: String,
    pub name: String,
    pub qualified_name: String,
    pub file_path: String,
    pub start_line: i64,
    pub end_line: i64,
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
pub struct CbmPipelineRows {
    pub project: String,
    pub nodes: Vec<CbmPipelineNodeRow>,
    pub edges: Vec<CbmPipelineEdgeRow>,
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
    error: Option<BridgeError>,
}

impl PipelineRowSinkState {
    fn new() -> Self {
        Self {
            owner: thread::current().id(),
            nodes: Vec::new(),
            edges: Vec::new(),
            error: None,
        }
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
        self.nodes.push(CbmPipelineNodeRow {
            id: row.id,
            project: required_borrowed_c_string(row.project, "row_sink.node.project")?,
            label: required_borrowed_c_string(row.label, "row_sink.node.label")?,
            name: required_borrowed_c_string(row.name, "row_sink.node.name")?,
            qualified_name: required_borrowed_c_string(
                row.qualified_name,
                "row_sink.node.qualified_name",
            )?,
            file_path: required_borrowed_c_string(row.file_path, "row_sink.node.file_path")?,
            start_line: i64::from(row.start_line),
            end_line: i64::from(row.end_line),
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

pub struct CbmPipeline {
    ptr: NonNull<cbm_sys::cbm_pipeline_t>,
    owner: ThreadId,
    _repo_path: CString,
    _db_path: CString,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl CbmPipeline {
    pub fn new(repo_path: &str, db_path: &str, mode: CbmIndexMode) -> Result<Self, BridgeError> {
        cbm_sys::initialize_allocator_bindings_first();
        let repo_path = CString::new(repo_path)?;
        let db_path = CString::new(db_path)?;
        // SAFETY: cbm_init is idempotent in libcbm. The repo/db strings outlive
        // pipeline creation and CBM copies the paths into the pipeline object.
        unsafe {
            map_cbm_status(cbm_sys::cbm_init())?;
            let ptr =
                cbm_sys::cbm_pipeline_new(repo_path.as_ptr(), db_path.as_ptr(), mode.as_raw());
            Ok(Self {
                ptr: NonNull::new(ptr).ok_or_else(|| {
                    envelope(
                        "ASTRO_CBM_PIPELINE_INIT",
                        "cbm_pipeline_new returned NULL",
                        "Check repository path validity and CBM startup diagnostics.",
                    )
                })?,
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
        // SAFETY: self owns the pipeline pointer. `sink` remains live until
        // cbm_pipeline_run returns, and the sink is cleared immediately after.
        let rc = unsafe {
            cbm_sys::cbm_pipeline_set_sink(
                self.ptr.as_ptr(),
                Some(pipeline_node_sink),
                Some(pipeline_edge_sink),
                (&mut sink as *mut PipelineRowSinkState).cast::<c_void>(),
            );
            let rc = cbm_sys::cbm_pipeline_run(self.ptr.as_ptr());
            cbm_sys::cbm_pipeline_set_sink(self.ptr.as_ptr(), None, None, ptr::null_mut());
            rc
        };

        if rc != 0 {
            if let Some(error) = sink.error {
                return Err(error);
            }
            map_cbm_status(rc)?;
        }
        if let Some(error) = sink.error {
            return Err(error);
        }
        let project = self.project_name()?;
        Ok(CbmPipelineRows {
            project,
            nodes: sink.nodes,
            edges: sink.edges,
        })
    }

    pub fn run_to_sqlite(&mut self) -> Result<(), BridgeError> {
        self.ensure_owner_thread()?;
        // SAFETY: self owns the pipeline pointer. Clearing the sink first makes
        // this the baseline no-row-sink path for benchmark and compatibility use.
        let rc = unsafe {
            cbm_sys::cbm_pipeline_set_sink(self.ptr.as_ptr(), None, None, ptr::null_mut());
            cbm_sys::cbm_pipeline_run(self.ptr.as_ptr())
        };
        map_cbm_status(rc)
    }

    pub fn set_project_name(&mut self, name: &str) -> Result<(), BridgeError> {
        self.ensure_owner_thread()?;
        let name = CString::new(name)?;
        // SAFETY: self owns the pipeline pointer. CBM copies and normalizes the
        // provided project name during the call.
        let accepted =
            unsafe { cbm_sys::cbm_pipeline_set_project_name(self.ptr.as_ptr(), name.as_ptr()) };
        if accepted {
            Ok(())
        } else {
            Err(envelope(
                "ASTRO_CBM_PIPELINE_PROJECT_NAME",
                "CBM rejected the requested pipeline project name",
                "Use a non-empty project name valid for CBM cache path construction.",
            ))
        }
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
        cbm_sys::initialize_allocator_bindings_first();
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
            let ptr = cbm_sys::cbm_extract_file(
                source.as_ptr().cast::<c_char>(),
                source_len,
                language.as_raw(),
                project.as_ptr(),
                rel_path.as_ptr(),
                timeout_micros,
                ptr::null_mut(),
                ptr::null_mut(),
            );
            let extracted = Self {
                ptr: NonNull::new(ptr).ok_or_else(|| {
                    envelope(
                        "ASTRO_CBM_NULL_RESULT",
                        "cbm_extract_file returned NULL",
                        "Check libcbm diagnostics and reject the file as an extraction failure.",
                    )
                })?,
                _source: source,
                _project: project,
                _rel_path: rel_path,
                _not_send_or_sync: PhantomData,
            };
            if extracted.raw().has_error {
                let message = extracted
                    .optional_string(extracted.raw().error_msg)?
                    .unwrap_or_else(|| {
                        "CBM extraction failed without an error message".to_string()
                    });
                Err(envelope(
                    "ASTRO_CBM_EXTRACT_ERROR",
                    message,
                    "Surface the file as skipped and continue indexing the remaining batch.",
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
                    local_name: self.required_string(item.local_name, "import.local_name")?,
                    module_path: self.required_string(item.module_path, "import.module_path")?,
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct Import {
    pub local_name: String,
    pub module_path: String,
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
pub struct Route {
    pub owner_qualified_name: String,
    pub path: String,
    pub method: Option<String>,
}

struct CbmStore {
    ptr: NonNull<cbm_sys::cbm_store_t>,
    _not_send_or_sync: PhantomData<Rc<()>>,
}

impl CbmStore {
    fn open_memory() -> Result<Self, BridgeError> {
        cbm_sys::initialize_allocator_bindings_first();
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
        // SAFETY: self uniquely owns the cbm_store_t pointer.
        unsafe {
            cbm_sys::cbm_store_close(self.ptr.as_ptr());
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
        cbm_sys::initialize_allocator_bindings_first();
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
        let tool_name = CString::new(tool_name)?;
        let args_json = CString::new(args_json)?;
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

    pub fn handle_index_repository_with_rows(
        &self,
        args_json: &str,
    ) -> Result<CbmIndexRepositoryRows, BridgeError> {
        self.ensure_owner_thread()?;
        let tool_name = CString::new("index_repository")?;
        let args_json = CString::new(args_json)?;
        let mut sink = PipelineRowSinkState::new();

        // SAFETY: server pointer is owned by self and thread-affine. `sink`
        // lives until cbm_mcp_handle_tool returns and is cleared immediately.
        let raw_result = unsafe {
            cbm_sys::cbm_mcp_server_set_row_sink(
                self.ptr.as_ptr(),
                Some(pipeline_node_sink),
                Some(pipeline_edge_sink),
                (&mut sink as *mut PipelineRowSinkState).cast::<c_void>(),
            );
            let ptr = cbm_sys::cbm_mcp_handle_tool(
                self.ptr.as_ptr(),
                tool_name.as_ptr(),
                args_json.as_ptr(),
            );
            cbm_sys::cbm_mcp_server_set_row_sink(self.ptr.as_ptr(), None, None, ptr::null_mut());
            take_c_string(ptr)
        };
        let raw_json = raw_result?;
        // #123: the index already ran to completion here — a row-sink failure is
        // returned ALONGSIDE the raw result rather than discarding it, so the
        // caller never has to rerun the whole index to recover the tool result.
        let rows = match sink.error {
            Some(error) => Err(error),
            None => {
                let project = project_from_tool_result(&raw_json)
                    .or_else(|| sink.nodes.first().map(|node| node.project.clone()))
                    .or_else(|| sink.edges.first().map(|edge| edge.project.clone()))
                    .unwrap_or_default();
                Ok(CbmPipelineRows {
                    project,
                    nodes: sink.nodes,
                    edges: sink.edges,
                })
            }
        };
        Ok(CbmIndexRepositoryRows { raw_json, rows })
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

#[cfg(test)]
mod tests {
    use super::*;

    // #253 FSV: a SYNCHRONIZE process handle becomes signaled the instant the process
    // exits, so ParentDeathWatch::wait must report StillAlive while a controlled child runs
    // and Exited once it is killed. Source of truth = the real OS process state; we read the
    // wait outcome back before and after the kill.
    #[cfg(windows)]
    #[test]
    fn parent_death_watch_reports_still_alive_then_exited() {
        use std::process::{Command, Stdio};
        // A child we fully own: ping loopback stays alive ~30s; killing it is the synthetic
        // "parent death" trigger. Spawned directly so child.id() is the process we watch.
        let mut child = Command::new("ping")
            .args(["-n", "30", "127.0.0.1"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn a controllable child process");
        let pid = child.id();
        let watch =
            ParentDeathWatch::open(pid).expect("open a SYNCHRONIZE handle to the live child");

        // BEFORE: the child is alive -> a zero-timeout wait must observe StillAlive.
        let before = watch.wait(0);
        eprintln!("[FSV #253] pid={pid} before-kill wait(0)  = {before:?}");
        assert!(
            matches!(before, ParentWaitOutcome::StillAlive),
            "expected StillAlive while the child runs, got {before:?}"
        );

        // Trigger the death and reap it: the OS process is now gone.
        child.kill().expect("kill the controlled child");
        let _ = child.wait();

        // AFTER: the handle must signal -> Exited within a bounded wait.
        let after = watch.wait(5_000);
        eprintln!("[FSV #253] pid={pid} after-kill  wait(5000)= {after:?}");
        assert!(
            matches!(after, ParentWaitOutcome::Exited),
            "expected Exited after the child was killed, got {after:?}"
        );
    }

    // #253: the parent-PID acquisition path (NtQueryInformationProcess) resolves on Windows
    // -- the test runner has a live parent -- and that PID is openable for a SYNCHRONIZE wait.
    #[cfg(windows)]
    #[test]
    fn parent_process_id_resolves_and_parent_is_watchable() {
        let ppid = parent_process_id();
        eprintln!("[FSV #253] parent_process_id() = {ppid:?}");
        let ppid = ppid.expect("the test runner has a parent; expected Some");
        assert_ne!(ppid, 0, "parent pid must be non-zero");
        let watch = ParentDeathWatch::open(ppid).expect("open a handle to our live parent");
        assert!(
            matches!(watch.wait(0), ParentWaitOutcome::StillAlive),
            "our parent is alive right now; wait(0) must be StillAlive"
        );
    }

    // #253 edge: opening a watch on a reaped PID must never silently claim liveness -- it
    // fails closed with the coded message, or (rare PID reuse) yields a real, honest handle.
    #[cfg(windows)]
    #[test]
    fn parent_death_watch_open_on_reaped_pid_never_lies() {
        let mut child = std::process::Command::new("cmd")
            .args(["/c", "exit", "0"])
            .spawn()
            .expect("spawn short-lived child");
        let pid = child.id();
        child
            .wait()
            .expect("reap the child so its PID is no longer a live process");
        match ParentDeathWatch::open(pid) {
            Err(message) => {
                eprintln!("[FSV #253] open(reaped pid {pid}) failed closed: {message}");
                assert!(
                    message.contains("ASTRO_WATCHDOG_PARENT_OPEN"),
                    "fail-closed error must carry the code, got {message}"
                );
            }
            Ok(watch) => {
                eprintln!(
                    "[FSV #253] open(reaped pid {pid}) succeeded (PID reuse); wait(0) = {:?}",
                    watch.wait(0)
                );
            }
        }
    }

    /// List the CBM store under `home` as (name, len) pairs, sorted. The source of
    /// truth for every store-isolation FSV: an override/refusal must leave it
    /// byte-identical.
    fn store_entries(home: &std::path::Path) -> Vec<(String, u64)> {
        let store = home.join(".cache").join("codebase-memory-mcp");
        let Ok(entries) = std::fs::read_dir(&store) else {
            return Vec::new();
        };
        let mut listing: Vec<(String, u64)> = entries
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| {
                let name = entry.file_name().to_string_lossy().into_owned();
                let len = entry.metadata().ok()?.len();
                Some((name, len))
            })
            .collect();
        listing.sort();
        listing
    }

    /// The CBM store under the process's INHERITED `HOME`. Used only inside child
    /// probes, which receive a per-run sandbox `HOME` from their parent (#248) — so
    /// this reads that sandbox, never the operator's real store.
    fn home_store_entries() -> Vec<(String, u64)> {
        let home = std::env::var("HOME")
            .ok()
            .filter(|value| !value.is_empty())
            .or_else(|| std::env::var("USERPROFILE").ok())
            .expect("HOME or USERPROFILE is set");
        store_entries(std::path::Path::new(&home))
    }

    /// #248: a per-run sandbox `HOME` so the store-isolation FSV never reads or
    /// asserts against the operator's real `~/.cache/codebase-memory-mcp`. The
    /// operator actively uses CBM (their real store holds live project dbs), so a
    /// concurrent index during the run would perturb a real-home byte-identity
    /// assertion — a false red unrelated to the code under test, and the exact
    /// coupling that blocked running the CBM-test and Rust gate phases concurrently.
    /// The store dir is pre-created so a `default`-case `canonicalize()` (which
    /// requires the path to exist) resolves against the sandbox instead of the
    /// operator's home. Lives under the (TMP-sandboxed, #246) test temp root.
    fn sandbox_home(name: &str) -> std::path::PathBuf {
        let home = temp_dir(name).join("home");
        std::fs::create_dir_all(home.join(".cache").join("codebase-memory-mcp"))
            .expect("create sandbox home store dir");
        home
    }

    #[test]
    fn cbm_store_path_capacity_matches_vendor_constant() {
        // Not a magic number: read the value CBM actually compiles with. The store
        // resolvers publish from a static char[CBM_SZ_1K], so that is the true bound.
        let constants = std::path::Path::new(cbm_sys::vendor_root())
            .join("src")
            .join("foundation")
            .join("constants.h");
        let source = std::fs::read_to_string(&constants).expect("vendored constants.h is readable");
        let declared = source
            .lines()
            .find_map(|line| line.trim().strip_prefix("CBM_SZ_1K = "))
            .and_then(|value| value.trim_end_matches(',').parse::<usize>().ok())
            .expect("constants.h declares CBM_SZ_1K");
        assert_eq!(
            declared, CBM_STORE_PATH_CAPACITY,
            "CBM_STORE_PATH_CAPACITY must track the vendored CBM_SZ_1K store buffer"
        );
    }

    #[test]
    fn store_env_validation_refuses_every_silent_degradation() {
        let absolute = if cfg!(windows) {
            "C:/code/Astrolabe/target/store"
        } else {
            "/var/tmp/store"
        };
        assert!(validate_cbm_store_env(Some(absolute), Some("/home/op"), None).is_ok());
        assert!(validate_cbm_store_env(None, Some("/home/op"), None).is_ok());
        assert!(validate_cbm_store_env(None, None, Some("C:/Users/op")).is_ok());

        let cases: [(Option<&str>, Option<&str>, &str); 4] = [
            // Empty: CBM copies "" into its buffer and falls back to the home store.
            (Some(""), Some("/home/op"), "ASTRO_CBM_CACHE_DIR_EMPTY"),
            // Relative: resolves against whatever cwd the process happens to have.
            (
                Some("relative/store"),
                Some("/home/op"),
                "ASTRO_CBM_CACHE_DIR_RELATIVE",
            ),
            // Over-long: cbm_safe_getenv truncates into a different directory.
            (
                Some(Box::leak(
                    format!(
                        "{}{}",
                        if cfg!(windows) { "C:/" } else { "/" },
                        "x".repeat(1100)
                    )
                    .into_boxed_str(),
                )),
                Some("/home/op"),
                "ASTRO_CBM_CACHE_DIR_TRUNCATED",
            ),
            (
                None,
                Some(Box::leak(
                    format!(
                        "{}{}",
                        if cfg!(windows) { "C:/" } else { "/" },
                        "h".repeat(1100)
                    )
                    .into_boxed_str(),
                )),
                "ASTRO_CBM_HOME_TRUNCATED",
            ),
        ];
        for (cache_dir, home, code) in cases {
            let error = validate_cbm_store_env(cache_dir, home, None)
                .expect_err("silent degradation must fail closed");
            assert_eq!(error.envelope().code, code, "wrong code for {cache_dir:?}");
            assert!(
                !error.envelope().remediation.is_empty(),
                "{code} must carry a remediation"
            );
        }
    }

    /// Child half of `cbm_cache_dir_edge_cases_fail_closed_without_touching_the_home_store`.
    ///
    /// The store environment is read by BOTH halves of this process — Rust's
    /// `std::env` and, inside libcbm, the C runtime's `environ` snapshot. On
    /// Windows those two views only agree on the environment the process
    /// *inherited*: `std::env::set_var` goes through `SetEnvironmentVariableW` and
    /// never reaches the CRT array `cbm_safe_getenv` walks. So each case is run in
    /// its own child process with the value inherited from the parent — which is
    /// also exactly how a real host receives it.
    #[test]
    #[ignore = "spawned as a subprocess by cbm_cache_dir_edge_cases_fail_closed_without_touching_the_home_store"]
    fn cbm_cache_dir_env_child_probe() {
        let case = std::env::var("ASTRO_BRIDGE_PROBE_CASE").expect("parent selects a case");
        let before = home_store_entries();

        match case.as_str() {
            // (a) CBM_CACHE_DIR is relative: CBM would resolve it against whatever
            // cwd the host happens to have and scatter the store.
            "relative" => {
                let raw = std::env::var("CBM_CACHE_DIR").expect("parent set the relative store");
                let error = cbm_cache_dir().expect_err("a relative store must fail closed");
                assert_eq!(error.envelope().code, "ASTRO_CBM_CACHE_DIR_RELATIVE");
                assert!(!error.envelope().remediation.is_empty());
                assert!(
                    !std::env::current_dir().expect("cwd").join(&raw).exists(),
                    "a refused resolve must not create a store under the cwd"
                );
            }
            // (b) CBM_CACHE_DIR names something that cannot hold a store.
            "occupied" => {
                let raw = std::env::var("CBM_CACHE_DIR").expect("parent set the blocked store");
                let error = cbm_cache_dir().expect_err("an unusable store must fail closed");
                assert_eq!(error.envelope().code, "ASTRO_CBM_CACHE_DIR_NOT_A_DIRECTORY");
                assert!(!error.envelope().remediation.is_empty());
                assert_eq!(
                    std::fs::read(&raw).expect("the blocking file survives"),
                    b"not a directory",
                    "a refused resolve must not clobber the path it refused"
                );
            }
            // (c) CBM_CACHE_DIR unset: the documented default store, and nothing else.
            "default" => {
                assert!(
                    std::env::var("CBM_CACHE_DIR").is_err(),
                    "parent cleared the override"
                );
                let resolved = cbm_cache_dir().expect("the default store resolves");
                let home = std::env::var("HOME")
                    .ok()
                    .filter(|value| !value.is_empty())
                    .or_else(|| std::env::var("USERPROFILE").ok())
                    .expect("HOME or USERPROFILE is set");
                let expected = std::path::Path::new(&home)
                    .join(".cache")
                    .join("codebase-memory-mcp");
                assert_eq!(
                    resolved.canonicalize().expect("resolved store exists"),
                    expected.canonicalize().expect("expected store exists"),
                    "the default store must stay $HOME/.cache/codebase-memory-mcp"
                );
            }
            other => panic!("unknown probe case {other}"),
        }

        // FSV: the operator's store is byte-identical after the case ran.
        assert_eq!(
            before,
            home_store_entries(),
            "the CBM store must be byte-identical after the {case} case"
        );
        println!("cbm_cache_dir store-env case passed: {case}");
    }

    #[test]
    fn cbm_cache_dir_edge_cases_fail_closed_without_touching_the_home_store() {
        let scratch = temp_dir("cache-env-probe");
        std::fs::create_dir_all(&scratch).expect("create the probe scratch dir");
        let occupied = scratch.join("occupied-store");
        std::fs::write(&occupied, b"not a directory").expect("write the blocking file");
        // #248: the child inherits a per-run sandbox HOME so the `default` case
        // resolves the sandbox store (not the operator's real ~/.cache) and the
        // byte-identity FSV below is hermetic.
        let test_home = sandbox_home("cache-env-home");
        let before = store_entries(&test_home);
        let exe = std::env::current_exe().expect("test binary path");

        let cases = [
            ("relative", Some("astro-relative-store".to_string())),
            (
                "occupied",
                Some(occupied.to_str().expect("utf-8 path").to_string()),
            ),
            ("default", None),
        ];
        for (case, cache_dir) in cases {
            let mut command = std::process::Command::new(&exe);
            command
                .args([
                    "--exact",
                    "tests::cbm_cache_dir_env_child_probe",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("ASTRO_BRIDGE_PROBE_CASE", case)
                .env("HOME", &test_home)
                .env("USERPROFILE", &test_home)
                .current_dir(&scratch);
            match &cache_dir {
                Some(value) => command.env("CBM_CACHE_DIR", value),
                None => command.env_remove("CBM_CACHE_DIR"),
            };
            let output = command.output().expect("spawn the store-env probe");
            let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
            assert!(
                output.status.success(),
                "store-env probe {case} failed:\n{stdout}\n{stderr}"
            );
            assert!(
                stdout.contains(&format!("store-env case passed: {case}")),
                "probe {case} did not run its assertions:\n{stdout}"
            );
        }

        assert_eq!(
            before,
            store_entries(&test_home),
            "the CBM store must be byte-identical after the edge-case triad"
        );
        std::fs::remove_dir_all(&scratch).ok();
    }

    // ── #240: explicit store configuration across the FFI boundary ──────────

    /// Child half of `set_cbm_cache_dir_relocates_the_persisted_store_on_disk`.
    ///
    /// The FFI override is process-global, so it runs in its own child to avoid
    /// leaking into sibling tests — the same isolation the env probes use. The
    /// parent hands it a store directory and a repo via the environment (which is
    /// safe: these are the child's INHERITED environment, read only by the Rust
    /// parent-child protocol, never by libcbm's store resolver).
    #[test]
    #[ignore = "spawned as a subprocess by set_cbm_cache_dir_relocates_the_persisted_store_on_disk"]
    fn set_cbm_cache_dir_child_probe() {
        let store = PathBuf::from(std::env::var("ASTRO_PROBE_STORE").expect("parent sets store"));
        let repo = std::env::var("ASTRO_PROBE_REPO").expect("parent sets repo");
        let before = home_store_entries();

        // Configure the store by PARAMETER, not by environment. The returned path
        // is libcbm's own resolver answer, independently confirmed below on disk.
        let resolved = set_cbm_cache_dir(&store).expect("libcbm accepts the explicit store");
        assert_eq!(
            resolved.canonicalize().expect("configured store exists"),
            store.canonicalize().expect("store dir created"),
            "libcbm must resolve the store to the configured directory"
        );

        // Drive a real index with a NULL db_path so libcbm resolves the database
        // location itself, through the overridden cache dir.
        cbm_sys::initialize_allocator_bindings_first();
        let repo_c = CString::new(repo).expect("repo cstring");
        let project = "ffi-store-demo";
        // SAFETY: raw pipeline lifecycle. db_path is NULL so libcbm resolves the DB
        // path via cbm_resolve_cache_dir(); the pipeline is freed before return.
        unsafe {
            assert_eq!(cbm_sys::cbm_init(), 0, "cbm_init");
            let p = cbm_sys::cbm_pipeline_new(
                repo_c.as_ptr(),
                ptr::null(),
                cbm_sys::cbm_index_mode_t_CBM_MODE_FULL,
            );
            assert!(!p.is_null(), "cbm_pipeline_new returned NULL");
            let name = CString::new(project).expect("project cstring");
            assert!(
                cbm_sys::cbm_pipeline_set_project_name(p, name.as_ptr()),
                "set project name"
            );
            let rc = cbm_sys::cbm_pipeline_run(p);
            cbm_sys::cbm_pipeline_free(p);
            assert_eq!(rc, 0, "pipeline run rc");
        }

        // Independent read of the source of truth: the SQLite artifact is under the
        // CONFIGURED store, and the operator's home store is untouched.
        let db = store.join(format!("{project}.db"));
        assert!(
            db.is_file(),
            "libcbm must persist {project}.db under the configured store {}; found: {:?}",
            store.display(),
            std::fs::read_dir(&store)
                .map(|d| d
                    .filter_map(|e| e.ok())
                    .map(|e| e.file_name())
                    .collect::<Vec<_>>())
                .unwrap_or_default()
        );
        let db_bytes = std::fs::read(&db).expect("read persisted store db");
        assert!(
            db_bytes.starts_with(b"SQLite format 3\0"),
            "the persisted store must be a real SQLite database"
        );

        clear_cbm_cache_dir();
        assert_eq!(
            before,
            home_store_entries(),
            "configuring a store by FFI parameter must not touch the home store"
        );
        println!("ffi-store relocate passed: {}", db.display());
    }

    /// FSV for #240: a store location set at RUNTIME through the FFI parameter
    /// must be the directory libcbm actually writes its index into — proving the
    /// configuration reached libcbm's C `environ`-reading resolver, which a
    /// `std::env::set_var` provably does not on Windows.
    ///
    /// Source of truth: the `<project>.db` file on disk. The pipeline is created
    /// with a NULL db_path (raw FFI) in the child, so libcbm resolves the database
    /// path through `cbm_resolve_cache_dir()` — the exact path the #240 override
    /// feeds. An echo of the resolver return value would not prove libcbm *used* it
    /// to persist; the SQLite file appearing under the configured dir does.
    #[test]
    fn set_cbm_cache_dir_relocates_the_persisted_store_on_disk() {
        let test_home = sandbox_home("ffi-store-home");
        let before = store_entries(&test_home);
        let dir = temp_dir("ffi-store-config");
        let store = dir.join("relocated-store");
        let repo = dir.join("repo");
        let src = repo.join("src");
        std::fs::create_dir_all(&src).expect("create fixture repo");
        std::fs::write(
            src.join("main.c"),
            "int helper(void) { return 41; }\nint main(void) { return helper() + 1; }\n",
        )
        .expect("write C fixture");

        let exe = std::env::current_exe().expect("test binary path");
        let mut command = std::process::Command::new(&exe);
        command
            .args([
                "--exact",
                "tests::set_cbm_cache_dir_child_probe",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("ASTRO_PROBE_STORE", &store)
            .env("ASTRO_PROBE_REPO", &repo)
            .env("HOME", &test_home)
            .env("USERPROFILE", &test_home);
        let output = command.output().expect("spawn the ffi-store probe");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(
            output.status.success(),
            "ffi-store relocate probe failed:\n{stdout}\n{stderr}"
        );
        assert!(
            stdout.contains("ffi-store relocate passed"),
            "probe did not run its assertions:\n{stdout}"
        );

        // Parent-side FSV: the SQLite store the child wrote is on disk under the
        // configured directory, and the operator's home store is byte-identical.
        let db = store.join("ffi-store-demo.db");
        assert!(
            db.is_file(),
            "the relocated store db must persist at {}",
            db.display()
        );
        assert_eq!(
            before,
            store_entries(&test_home),
            "configuring a store by FFI parameter must not touch the home store"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    // ── #241: fail-closed environment truncation + unresolvable store ───────

    /// Child probe (#241): a real inherited env var longer than the store buffer
    /// makes libcbm's `cbm_safe_getenv` publish a coded truncation fault rather
    /// than silently resolving a different directory. Run in a child so the value
    /// is INHERITED (the only way the C `environ` array sees it — the same reason
    /// #240 exists).
    #[test]
    #[ignore = "spawned as a subprocess by cbm_env_truncation_and_unresolvable_fail_closed"]
    fn cbm_env_fault_child_probe() {
        let case = std::env::var("ASTRO_BRIDGE_ENV_FAULT_CASE").expect("parent selects a case");
        // The home-store invariant only applies when a home exists; the
        // "unresolvable" case deliberately unsets HOME/USERPROFILE, so there is no
        // home store to hold byte-identical.
        let before = (case != "unresolvable").then(home_store_entries);
        cbm_sys::initialize_allocator_bindings_first();
        unsafe { cbm_sys::cbm_astro_env_fault_clear() };

        match case.as_str() {
            // An over-long CBM_CACHE_DIR must fail closed at BOTH layers, and this
            // case proves each independently.
            "truncated" => {
                let raw = std::env::var("CBM_CACHE_DIR").expect("parent set the long store");
                println!("env-fault CBM_CACHE_DIR length before: {}", raw.len());

                // (a) Production path: cbm_cache_dir()'s Rust guard refuses the
                // over-long value before it ever reaches C — defense in depth. This
                // is the code every server store resolution actually runs.
                let error = cbm_cache_dir().expect_err("an over-long store must fail closed");
                assert_eq!(error.envelope().code, "ASTRO_CBM_CACHE_DIR_TRUNCATED");
                assert!(!error.envelope().remediation.is_empty());

                // (b) C layer: bypass the Rust guard and drive libcbm's own resolver
                // directly, proving the overlay's cbm_safe_getenv detects the
                // truncation and refuses with a NULL path + named fault instead of
                // silently resolving a different (truncated) directory — the #241
                // vendored defect. FSV: read the C resolver's return AND its fault.
                unsafe { cbm_sys::cbm_astro_env_fault_clear() };
                let ptr = unsafe { cbm_sys::cbm_resolve_cache_dir() };
                assert!(
                    ptr.is_null(),
                    "a truncated CBM_CACHE_DIR must resolve to NULL, not a cut path"
                );
                let code = unsafe { cbm_sys::cbm_astro_env_fault_code() };
                assert!(
                    !code.is_null(),
                    "the C resolver must publish a truncation fault"
                );
                let code = unsafe { CStr::from_ptr(code) }
                    .to_string_lossy()
                    .into_owned();
                assert_eq!(code, "CBM_E_ENV_VALUE_TRUNCATED");
                assert_eq!(
                    unsafe { cbm_sys::cbm_astro_env_faulted_for(c"CBM_CACHE_DIR".as_ptr()) },
                    1,
                    "the fault must name CBM_CACHE_DIR as the offender"
                );
                unsafe { cbm_sys::cbm_astro_env_fault_clear() };
            }
            // No override, no CBM_CACHE_DIR, no HOME/USERPROFILE: the store is
            // unresolvable and must be a NAMED refusal, never UB or "(null)".
            "unresolvable" => {
                assert!(
                    std::env::var("CBM_CACHE_DIR").is_err(),
                    "parent cleared override"
                );
                assert!(std::env::var("HOME").is_err(), "parent cleared HOME");
                assert!(
                    std::env::var("USERPROFILE").is_err(),
                    "parent cleared USERPROFILE"
                );
                let ptr = unsafe { cbm_sys::cbm_resolve_cache_dir() };
                assert!(ptr.is_null(), "no home means no store");
                let code = unsafe { cbm_sys::cbm_astro_env_fault_code() };
                assert!(
                    !code.is_null(),
                    "an unresolvable store must publish a fault"
                );
                let code = unsafe { CStr::from_ptr(code) }
                    .to_string_lossy()
                    .into_owned();
                assert_eq!(code, "CBM_E_STORE_UNRESOLVABLE");
                unsafe { cbm_sys::cbm_astro_env_fault_clear() };
            }
            other => panic!("unknown env-fault case {other}"),
        }

        if let Some(before) = before {
            assert_eq!(
                before,
                home_store_entries(),
                "a refused resolve must leave the home store byte-identical ({case})"
            );
        }
        println!("env-fault case passed: {case}");
    }

    #[test]
    fn cbm_env_truncation_and_unresolvable_fail_closed() {
        let test_home = sandbox_home("env-fault-home");
        let before = store_entries(&test_home);
        let exe = std::env::current_exe().expect("test binary path");
        // A store path longer than the CBM_SZ_1K result buffer. Absolute so only the
        // length — not the relative-path guard — is what condemns it.
        let over_long = format!(
            "{}{}",
            if cfg!(windows) { "C:/" } else { "/" },
            "L".repeat(CBM_STORE_PATH_CAPACITY + 64)
        );

        // Case 1: over-long inherited CBM_CACHE_DIR → coded truncation refusal.
        let mut truncated = std::process::Command::new(&exe);
        truncated
            .args([
                "--exact",
                "tests::cbm_env_fault_child_probe",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("ASTRO_BRIDGE_ENV_FAULT_CASE", "truncated")
            .env("CBM_CACHE_DIR", &over_long)
            .env("HOME", &test_home)
            .env("USERPROFILE", &test_home);
        let out = truncated.output().expect("spawn truncation probe");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(
            out.status.success(),
            "truncation probe failed:\n{stdout}\n{stderr}"
        );
        assert!(
            stdout.contains("env-fault case passed: truncated"),
            "truncation probe did not assert:\n{stdout}"
        );
        assert!(
            stderr.contains("ERROR[CBM_E_ENV_VALUE_TRUNCATED]"),
            "the C half must print the fail-closed envelope on stderr:\n{stderr}"
        );

        // Case 2: no store resolvable at all → named CBM_E_STORE_UNRESOLVABLE.
        let mut unresolvable = std::process::Command::new(&exe);
        unresolvable
            .args([
                "--exact",
                "tests::cbm_env_fault_child_probe",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("ASTRO_BRIDGE_ENV_FAULT_CASE", "unresolvable")
            .env_remove("CBM_CACHE_DIR")
            .env_remove("HOME")
            .env_remove("USERPROFILE");
        let out = unresolvable.output().expect("spawn unresolvable probe");
        let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
        assert!(
            out.status.success(),
            "unresolvable probe failed:\n{stdout}\n{stderr}"
        );
        assert!(
            stdout.contains("env-fault case passed: unresolvable"),
            "unresolvable probe did not assert:\n{stdout}"
        );
        assert!(
            stderr.contains("ERROR[CBM_E_STORE_UNRESOLVABLE]"),
            "an unresolvable store must print its named envelope:\n{stderr}"
        );

        assert_eq!(
            before,
            store_entries(&test_home),
            "the fail-closed env probes must leave the home store byte-identical"
        );
    }

    // ── #267: find_in_path reads an oversized PATH without truncation ──────────

    /// Child probe (#267): the install PLAN detects agent CLIs by searching PATH
    /// (cbm_install_plan_json -> cbm_build_install_plan_json -> cbm_detect_agents
    /// -> cbm_find_cli -> find_in_path). A developer PATH routinely exceeds the
    /// retired 4096-byte buffer; run in a child so the big PATH is INHERITED (the
    /// only way libcbm's C `environ` sees it — the #240 trap). FSV: after the plan
    /// call, read the C fault state back and assert find_in_path recorded NO PATH
    /// truncation fault.
    #[test]
    #[ignore = "spawned as a subprocess by cbm_install_plan_reads_oversized_path_without_truncation"]
    fn cbm_path_buffer_child_probe() {
        let case = std::env::var("ASTRO_BRIDGE_PATH_CASE").expect("parent selects a case");
        let path_len = std::env::var_os("PATH").map(|p| p.len()).unwrap_or(0);
        println!("path-buffer case={case} PATH_bytes_before={path_len}");
        cbm_sys::initialize_allocator_bindings_first();
        unsafe { cbm_sys::cbm_astro_env_fault_clear() };

        let home = sandbox_home("path-buffer-home");
        let binary = std::env::current_exe().expect("test binary path");
        let plan = cbm_install_plan_json(
            home.to_str().expect("utf8 home"),
            binary.to_str().expect("utf8 binary"),
        )
        .expect("install plan must be produced even with a large PATH");
        assert!(!plan.is_empty(), "install plan JSON must be non-empty");

        // Source of truth = libcbm's process-global env-fault record. On the retired
        // fixed-4096 buffer, find_in_path's cbm_safe_getenv("PATH", ...) truncates
        // any PATH > 4095 bytes and records CBM_E_ENV_VALUE_TRUNCATED for PATH. The
        // fix reads PATH into a heap buffer sized to its real length, so no fault.
        let path_faulted = unsafe { cbm_sys::cbm_astro_env_faulted_for(c"PATH".as_ptr()) };
        println!(
            "path-buffer case={case} plan_bytes={} PATH_bytes={path_len} path_faulted={path_faulted}",
            plan.len()
        );
        assert_eq!(
            path_faulted, 0,
            "find_in_path must read PATH ({path_len} bytes) in full without a truncation fault ({case})"
        );
        unsafe { cbm_sys::cbm_astro_env_fault_clear() };
        println!("path-buffer case passed: {case}");
    }

    /// #267 X+X=Y: drive the install-plan agent search under PATHs that exceed the
    /// retired 4096-byte buffer and assert no truncation fault fires. On the old
    /// fixed buffer these cases emit `store.env.fault var=PATH` (reproduced in the
    /// #248/native aggregate); with the heap-sized read they do not. The real PATH
    /// is kept as a suffix so the child process still launches; the junk prefix
    /// only inflates the byte length past 4096.
    #[test]
    fn cbm_install_plan_reads_oversized_path_without_truncation() {
        let exe = std::env::current_exe().expect("test binary path");
        let real = std::env::var("PATH").unwrap_or_default();
        let seg = if cfg!(windows) {
            "C:\\astro267\\seg"
        } else {
            "/astro267/seg"
        };
        let sep = if cfg!(windows) { ";" } else { ":" };
        let make = |target: usize| -> String {
            let mut s = String::new();
            let mut i = 0usize;
            while s.len() < target {
                s.push_str(&format!("{seg}{i:06}{sep}"));
                i += 1;
            }
            s.push_str(&real);
            s
        };
        // baseline (real PATH), operator-size (~4226 B), and ~8 KB.
        let cases = [
            ("baseline", real.clone()),
            ("oversize_4226", make(4226)),
            ("oversize_8192", make(8192)),
        ];
        for (case, path_value) in cases {
            if case != "baseline" {
                assert!(
                    path_value.len() > 4096,
                    "[{case}] PATH must exceed the retired 4096 buffer: {}",
                    path_value.len()
                );
            }
            let mut child = std::process::Command::new(&exe);
            child
                .args([
                    "--exact",
                    "tests::cbm_path_buffer_child_probe",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env("ASTRO_BRIDGE_PATH_CASE", case)
                .env("PATH", &path_value);
            let out = child.output().expect("spawn path-buffer probe");
            let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
            let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
            assert!(
                out.status.success(),
                "[{case}] probe failed:\n{stdout}\n{stderr}"
            );
            assert!(
                stdout.contains(&format!("path-buffer case passed: {case}")),
                "[{case}] probe did not assert:\n{stdout}"
            );
            // The heart of #267: no PATH truncation envelope on stderr (the C half
            // prints ERROR[CBM_E_ENV_VALUE_TRUNCATED] on a fixed-buffer truncation).
            assert!(
                !stderr.contains("CBM_E_ENV_VALUE_TRUNCATED"),
                "[{case}] find_in_path truncated PATH -- the #267 defect:\n{stderr}"
            );
        }
    }

    /// #241 edge-case triad for the explicit setter, printing state before/after:
    /// empty input, over-limit input, and a NULL-equivalent (relative) path.
    ///
    /// Each input is rejected by Rust-side validation before any FFI call, so the
    /// test never mutates libcbm's process-global override or fault state.
    #[test]
    fn set_cbm_cache_dir_edge_triad_fails_closed() {
        let test_home = sandbox_home("edge-triad-home");
        let before = store_entries(&test_home);
        cbm_sys::initialize_allocator_bindings_first();

        // Empty.
        eprintln!("edge[empty] before: no override installed");
        let empty = set_cbm_cache_dir(std::path::Path::new(""))
            .expect_err("an empty store path must fail closed");
        assert_eq!(empty.envelope().code, "ASTRO_CBM_CACHE_DIR_EMPTY");

        // Over-limit.
        let long = format!(
            "{}{}",
            if cfg!(windows) { "C:/" } else { "/" },
            "L".repeat(CBM_STORE_PATH_CAPACITY + 32)
        );
        eprintln!("edge[over-limit] before: length {}", long.len());
        let over = set_cbm_cache_dir(std::path::Path::new(&long))
            .expect_err("an over-long store path must fail closed");
        assert_eq!(over.envelope().code, "ASTRO_CBM_CACHE_DIR_TRUNCATED");

        // Invalid format: a relative path would resolve against cwd.
        eprintln!("edge[relative] before: relative candidate");
        let rel = set_cbm_cache_dir(std::path::Path::new("relative/store"))
            .expect_err("a relative store path must fail closed");
        assert_eq!(rel.envelope().code, "ASTRO_CBM_CACHE_DIR_RELATIVE");

        // After: no override took effect, so the resolver falls back to the default
        // and the home store is untouched.
        clear_cbm_cache_dir();
        assert!(
            unsafe { cbm_sys::cbm_astro_cache_dir_override() }.is_null(),
            "no refused edge case may leave an override installed"
        );
        eprintln!("edge triad after: override null, home store preserved");
        assert_eq!(
            before,
            store_entries(&test_home),
            "the edge triad must leave the home store byte-identical"
        );
    }

    struct PanicOnLogEventSubscriber {
        levels: std::sync::Arc<std::sync::Mutex<Vec<tracing::Level>>>,
    }

    impl tracing::Subscriber for PanicOnLogEventSubscriber {
        fn enabled(&self, _metadata: &tracing::Metadata<'_>) -> bool {
            true
        }

        fn new_span(&self, _span: &tracing::span::Attributes<'_>) -> tracing::span::Id {
            tracing::span::Id::from_u64(1)
        }

        fn record(&self, _span: &tracing::span::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _span: &tracing::span::Id, _follows: &tracing::span::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            self.levels
                .lock()
                .expect("log level recorder is not poisoned")
                .push(*event.metadata().level());
            panic!("tracing subscriber panic probe");
        }

        fn enter(&self, _span: &tracing::span::Id) {}

        fn exit(&self, _span: &tracing::span::Id) {}
    }

    #[inline(never)]
    fn move_watcher_callback_owner(owner: WatcherCallbackOwner) -> WatcherCallbackOwner {
        owner
    }

    #[test]
    fn exposes_both_parent_roots() {
        let (calyx, cbm) = parent_roots();
        assert!(calyx.ends_with("vendor/calyx"));
        assert!(cbm.ends_with("vendor/codebase-memory-mcp"));
    }

    #[test]
    fn cbm_log_tracing_sink_contains_subscriber_panics_and_preserves_levels() {
        let levels = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
        let subscriber = PanicOnLogEventSubscriber {
            levels: std::sync::Arc::clone(&levels),
        };

        tracing::subscriber::with_default(subscriber, || {
            // SAFETY: NULL is an explicitly supported no-op input.
            unsafe { cbm_log_tracing_sink(ptr::null()) };
            for line in [
                "level=error msg=error",
                "level=warn msg=warn",
                "level=debug msg=debug",
                "level=info msg=info",
            ] {
                let line = CString::new(line).expect("test log line has no NUL");
                // SAFETY: line remains live and NUL-terminated for this call.
                unsafe { cbm_log_tracing_sink(line.as_ptr()) };
            }
        });

        assert_eq!(
            *levels.lock().expect("log level recorder is not poisoned"),
            [
                tracing::Level::ERROR,
                tracing::Level::WARN,
                tracing::Level::DEBUG,
                tracing::Level::INFO,
            ]
        );
    }

    #[test]
    fn cbm_memory_budget_initializes_to_nonzero_bytes() {
        assert!(cbm_memory_budget_bytes() > 0);
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        std::env::temp_dir().join(format!(
            "astrolabe-bridge-{name}-{}-{nanos}",
            std::process::id()
        ))
    }

    fn cleanup_cbm_project_db(project: &str) {
        let Ok(cache_dir) = cbm_cache_dir() else {
            return;
        };
        let path = cache_dir.join(format!("{project}.db"));
        for suffix in ["", "-wal", "-shm", "-journal"] {
            let mut raw = path.as_os_str().to_os_string();
            raw.push(suffix);
            std::fs::remove_file(std::path::PathBuf::from(raw)).ok();
        }
    }

    /// RAII guard that deletes a codebase-memory-mcp project's persisted `.db`
    /// (plus WAL/SHM/journal sidecars) from the resolved cache dir on drop —
    /// including during panic unwind. A tool-runner test registers a project via
    /// `cbm_mcp_server_new(NULL)` + `index_repository`, which persists
    /// `<cbm_cache_dir()>/<project>.db`; a plain post-assert cleanup is fail-open
    /// (skipped when an earlier assertion panics), leaking the registration into
    /// the operator's global CBM store. Cleaning on drop makes teardown
    /// fail-closed regardless of assertion outcome (#194).
    struct CbmProjectDbGuard {
        project: String,
    }

    impl Drop for CbmProjectDbGuard {
        fn drop(&mut self) {
            cleanup_cbm_project_db(&self.project);
        }
    }

    #[test]
    fn extracts_fixture_with_owned_accessors() {
        let file = ExtractedFile::extract(
            include_str!("../../cbm-sys/fixtures/simple.c"),
            Language::C,
            "astrolabe_fixture",
            "src/simple.c",
            0,
        )
        .unwrap();

        let defs = file.definitions().unwrap();
        assert_eq!(defs.len(), 3);
        assert_eq!(defs[0].name, "src/simple.c");
        assert_eq!(defs[0].qualified_name, "astrolabe_fixture.src.simple");
        assert_eq!(defs[0].label, "Module");
        assert_eq!(defs[0].start_line, 1);
        assert_eq!(defs[0].end_line, 8);
        assert_eq!(defs[1].name, "helper");
        assert_eq!(
            defs[1].qualified_name,
            "astrolabe_fixture.src.simple.helper"
        );
        assert_eq!(defs[1].start_line, 1);
        assert_eq!(defs[1].end_line, 3);
        assert_eq!(defs[2].name, "add");
        assert_eq!(defs[2].qualified_name, "astrolabe_fixture.src.simple.add");
        assert_eq!(defs[2].start_line, 5);
        assert_eq!(defs[2].end_line, 7);

        let calls = file.calls().unwrap();
        assert!(calls.iter().any(|call| call.callee_name == "helper"));
        assert!(file.imports().unwrap().is_empty());
        let _ = file.usages().unwrap();
        let _ = file.read_writes().unwrap();
        let _ = file.throws().unwrap();
        let _ = file.type_refs().unwrap();
        let _ = file.channels().unwrap();
        assert!(file.routes().unwrap().is_empty());
    }

    #[test]
    fn pipeline_row_collector_matches_persisted_sqlite_counts() {
        let dir = temp_dir("pipeline-row-collector");
        let repo = dir.join("repo");
        let src = repo.join("src");
        std::fs::create_dir_all(&src).expect("create fixture repo");
        std::fs::write(
            src.join("main.c"),
            "int helper(void) { return 41; }\nint main(void) { return helper() + 1; }\n",
        )
        .expect("write C fixture");
        let db = dir.join("graph.db");

        let mut pipeline = CbmPipeline::new(
            repo.to_str().expect("utf8 repo path"),
            db.to_str().expect("utf8 db path"),
            CbmIndexMode::Full,
        )
        .expect("create CBM pipeline");
        pipeline
            .set_project_name("row-sink-demo")
            .expect("override CBM project name");
        let rows = pipeline.collect_rows().expect("collect row-sink rows");

        assert_eq!(rows.project, "row-sink-demo");
        assert!(
            rows.nodes
                .iter()
                .any(|node| node.qualified_name.ends_with(".main")),
            "expected main function in row sink: {rows:?}"
        );
        assert!(rows.nodes.iter().all(|node| node.project == rows.project));
        assert!(rows.edges.iter().all(|edge| edge.project == rows.project));
        assert!(
            rows.edges
                .iter()
                .all(|edge| edge.source_id > 0 && edge.target_id > 0)
        );

        let connection = rusqlite::Connection::open(&db).expect("open CBM sqlite");
        let node_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM nodes WHERE project = ?1",
                [rows.project.as_str()],
                |row| row.get(0),
            )
            .expect("count sqlite nodes");
        let edge_count: i64 = connection
            .query_row(
                "SELECT COUNT(*) FROM edges WHERE project = ?1",
                [rows.project.as_str()],
                |row| row.get(0),
            )
            .expect("count sqlite edges");
        assert_eq!(usize::try_from(node_count).unwrap(), rows.nodes.len());
        assert_eq!(usize::try_from(edge_count).unwrap(), rows.edges.len());

        drop(connection);
        drop(pipeline);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn tool_runner_index_repository_collects_rows_from_single_mcp_run() {
        // #246/#248: the tool-runner index must land in a RUN-SCOPED store, never the
        // operator's ~/.cache. `set_cbm_cache_dir` is a process-global override, so the
        // work runs in a spawned child (the `set_cbm_cache_dir_child_probe` pattern) to
        // stay isolated from sibling test threads; the parent then FSV-asserts the
        // operator home store is byte-identical.
        let test_home = sandbox_home("tool-runner-row-sink-home");
        let before = store_entries(&test_home);
        let dir = temp_dir("tool-runner-row-sink");
        let store = dir.join("store");
        let repo = dir.join("repo");
        let src = repo.join("src");
        std::fs::create_dir_all(&src).expect("create fixture repo");
        std::fs::write(
            src.join("main.c"),
            "int helper(void) { return 41; }\nint main(void) { return helper() + 1; }\n",
        )
        .expect("write C fixture");

        let exe = std::env::current_exe().expect("test binary path");
        let output = std::process::Command::new(&exe)
            .args([
                "--exact",
                "tests::tool_runner_collect_rows_child_probe",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("ASTRO_PROBE_STORE", &store)
            .env("ASTRO_PROBE_REPO", &repo)
            .env("HOME", &test_home)
            .env("USERPROFILE", &test_home)
            .output()
            .expect("spawn the tool-runner row-sink probe");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(
            output.status.success(),
            "tool-runner row-sink probe failed:\n{stdout}\n{stderr}"
        );
        assert!(
            stdout.contains("tool-runner collect-rows probe passed"),
            "probe did not run its assertions:\n{stdout}"
        );
        assert_eq!(
            before,
            store_entries(&test_home),
            "a run-scoped tool-runner index must not touch the operator home store"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    #[ignore = "spawned as a subprocess by tool_runner_index_repository_collects_rows_from_single_mcp_run"]
    fn tool_runner_collect_rows_child_probe() {
        let store = PathBuf::from(std::env::var("ASTRO_PROBE_STORE").expect("parent sets store"));
        let repo = std::env::var("ASTRO_PROBE_REPO").expect("parent sets repo");
        std::fs::create_dir_all(&store).expect("create run-scoped store");
        let before = home_store_entries();
        let resolved = set_cbm_cache_dir(&store).expect("configure run-scoped store");
        assert_eq!(
            resolved.canonicalize().expect("configured store exists"),
            store.canonicalize().expect("store dir created"),
            "libcbm must resolve the run-scoped store"
        );
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        let project = format!("row-sink-tool-{}-{nanos}", std::process::id());
        let args = serde_json::json!({
            "repo_path": repo,
            "mode": "full",
            "name": project,
        })
        .to_string();
        let db = store.join(format!("{project}.db"));
        {
            // Fail-closed teardown from the RUN-SCOPED store even on panic (#194).
            let _db_guard = CbmProjectDbGuard {
                project: project.clone(),
            };
            let runner = CbmToolRunner::new_default().expect("create CBM tool runner");
            let run = runner
                .handle_index_repository_with_rows(&args)
                .expect("single MCP index_repository run with row sink");
            let value: serde_json::Value =
                serde_json::from_str(&run.raw_json).expect("valid MCP tool result JSON");
            assert_eq!(
                value.get("isError").and_then(serde_json::Value::as_bool),
                Some(false)
            );
            assert_eq!(
                project_from_tool_result(&run.raw_json).as_deref(),
                Some(project.as_str())
            );
            let rows = run.rows.expect("row sink capture for the completed run");
            assert_eq!(rows.project, project);
            assert!(
                rows.nodes
                    .iter()
                    .any(|node| node.qualified_name.ends_with(".main")),
                "expected main function in MCP row sink: {rows:?}",
            );
            assert!(rows.nodes.iter().all(|node| node.project == rows.project));
            assert!(rows.edges.iter().all(|edge| edge.project == rows.project));
            // FSV: the SQLite db is under the RUN-SCOPED store, not the home store.
            assert!(
                db.is_file(),
                "index_repository must persist {project}.db under the run-scoped store {}; found: {:?}",
                store.display(),
                std::fs::read_dir(&store)
                    .map(|d| d
                        .filter_map(|e| e.ok())
                        .map(|e| e.file_name())
                        .collect::<Vec<_>>())
                    .unwrap_or_default()
            );
        } // guard drops here -> fail-closed teardown from the run-scoped store
        clear_cbm_cache_dir();
        assert_eq!(
            before,
            home_store_entries(),
            "a run-scoped tool-runner index must not touch the operator home store"
        );
        println!("tool-runner collect-rows probe passed: {}", db.display());
    }

    /// Regression for #194: prove — by reading the persisted `.db` file on disk
    /// (full state verification, not a return value) — that a tool-runner
    /// `index_repository` run registers exactly one project db and that teardown
    /// removes it, leaving zero store residue. #246/#248: the store is now
    /// RUN-SCOPED (never the operator's ~/.cache), set in a spawned child because
    /// `set_cbm_cache_dir` is a process-global override; the parent additionally
    /// FSV-asserts the operator home store is byte-identical.
    #[test]
    fn tool_runner_index_repository_leaves_no_store_residue() {
        let test_home = sandbox_home("tool-runner-residue-home");
        let before = store_entries(&test_home);
        let dir = temp_dir("tool-runner-residue");
        let store = dir.join("store");
        let repo = dir.join("repo");
        let src = repo.join("src");
        std::fs::create_dir_all(&src).expect("create fixture repo");
        std::fs::write(
            src.join("main.c"),
            "int helper(void) { return 41; }\nint main(void) { return helper() + 1; }\n",
        )
        .expect("write C fixture");

        let exe = std::env::current_exe().expect("test binary path");
        let output = std::process::Command::new(&exe)
            .args([
                "--exact",
                "tests::tool_runner_residue_child_probe",
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ])
            .env("ASTRO_PROBE_STORE", &store)
            .env("ASTRO_PROBE_REPO", &repo)
            .env("HOME", &test_home)
            .env("USERPROFILE", &test_home)
            .output()
            .expect("spawn the tool-runner residue probe");
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        assert!(
            output.status.success(),
            "tool-runner residue probe failed:\n{stdout}\n{stderr}"
        );
        assert!(
            stdout.contains("tool-runner residue probe passed"),
            "probe did not run its assertions:\n{stdout}"
        );
        assert_eq!(
            before,
            store_entries(&test_home),
            "a run-scoped tool-runner index must not touch the operator home store"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    #[ignore = "spawned as a subprocess by tool_runner_index_repository_leaves_no_store_residue"]
    fn tool_runner_residue_child_probe() {
        let store = PathBuf::from(std::env::var("ASTRO_PROBE_STORE").expect("parent sets store"));
        let repo = std::env::var("ASTRO_PROBE_REPO").expect("parent sets repo");
        std::fs::create_dir_all(&store).expect("create run-scoped store");
        let before = home_store_entries();
        set_cbm_cache_dir(&store).expect("configure run-scoped store");
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        let project = format!("row-sink-residue-{}-{nanos}", std::process::id());
        let args = serde_json::json!({
            "repo_path": repo,
            "mode": "full",
            "name": project,
        })
        .to_string();

        let cache_dir = cbm_cache_dir().expect("resolve CBM cache dir");
        assert_eq!(
            cache_dir.canonicalize().expect("run-scoped store exists"),
            store.canonicalize().expect("store dir created"),
            "cbm_cache_dir must resolve to the run-scoped store, not the operator home"
        );
        let db_path = cache_dir.join(format!("{project}.db"));
        // Precondition: nonexistent before the run.
        assert!(
            !db_path.exists(),
            "precondition violated: project db already present before index: {}",
            db_path.display()
        );

        {
            let _db_guard = CbmProjectDbGuard {
                project: project.clone(),
            };
            let runner = CbmToolRunner::new_default().expect("create CBM tool runner");
            let run = runner
                .handle_index_repository_with_rows(&args)
                .expect("single MCP index_repository run with row sink");
            assert_eq!(run.rows.expect("row sink capture").project, project);
            // Mid-run source-of-truth read: the registration exists on disk in the
            // run-scoped store.
            assert!(
                db_path.exists(),
                "index_repository must persist the project db at {}",
                db_path.display()
            );
        } // guard drops here -> fail-closed teardown

        // Post-teardown source-of-truth read: registration removed, zero residue.
        assert!(
            !db_path.exists(),
            "teardown must delete the project db (store residue leaked): {}",
            db_path.display()
        );
        for suffix in ["-wal", "-shm", "-journal"] {
            let mut raw = db_path.as_os_str().to_os_string();
            raw.push(suffix);
            let sidecar = std::path::PathBuf::from(raw);
            assert!(
                !sidecar.exists(),
                "teardown must delete sidecar {}",
                sidecar.display()
            );
        }
        clear_cbm_cache_dir();
        assert_eq!(
            before,
            home_store_entries(),
            "a run-scoped tool-runner index must not touch the operator home store"
        );
        println!("tool-runner residue probe passed: {}", db_path.display());
    }

    #[test]
    fn create_use_drop_extracted_file_repeatedly() {
        for _ in 0..1000 {
            let file = ExtractedFile::extract(
                include_str!("../../cbm-sys/fixtures/simple.c"),
                Language::C,
                "astrolabe_fixture",
                "src/simple.c",
                0,
            )
            .unwrap();
            assert_eq!(file.definitions().unwrap().len(), 3);
        }
    }

    #[test]
    fn maps_documented_status_codes() {
        assert!(map_cbm_status(cbm_sys::CBM_STORE_OK as i32).is_ok());
        assert_eq!(
            map_cbm_status(cbm_sys::CBM_STORE_ERR)
                .unwrap_err()
                .envelope()
                .code,
            "ASTRO_CBM_STATUS_ERR"
        );
        assert_eq!(
            map_cbm_status(cbm_sys::CBM_STORE_NOT_FOUND)
                .unwrap_err()
                .envelope()
                .code,
            "ASTRO_CBM_NOT_FOUND"
        );
        let unknown = map_cbm_status(-444).unwrap_err();
        assert_eq!(unknown.envelope().code, "ASTRO_CBM_INTERNAL");
        assert!(unknown.envelope().stderr.is_some());
    }

    #[test]
    fn installer_plan_wrapper_is_record_only_json() {
        let dir = temp_dir("installer-plan");
        std::fs::create_dir_all(&dir).expect("create installer plan home");
        let binary = dir.join("codebase-memory-mcp.exe");
        let plan = cbm_install_plan_json(dir.to_str().unwrap(), binary.to_str().unwrap()).unwrap();
        let value: serde_json::Value = serde_json::from_str(&plan).unwrap();
        assert_eq!(value["type"], "agent.install.plan.v1");
        assert_eq!(value["writes_started"], false);
        assert_eq!(value["network_after_install"], false);
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn owned_string_wrappers_release_through_cbm() {
        let dir = temp_dir("owned-strings");
        std::fs::create_dir_all(&dir).expect("create owned-string fixture directory");
        let path = dir.to_str().expect("utf8 fixture path");
        let binary = dir.join("codebase-memory-mcp.exe");

        assert!(!cbm_project_name_from_path(path).unwrap().is_empty());
        let plan = cbm_install_plan_json(path, binary.to_str().expect("utf8 binary path")).unwrap();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&plan).unwrap()["type"],
            "agent.install.plan.v1"
        );

        let runner = CbmToolRunner::new(":memory:").expect("create in-memory CBM tool runner");
        let tool = runner
            .handle_tool_raw("not_a_tool", "{}")
            .expect("CBM tool error response string");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&tool).unwrap()["isError"],
            true
        );
        let response = runner
            .handle_jsonrpc_raw(r#"{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}"#)
            .expect("CBM JSON-RPC response")
            .expect("tools/list is not a notification");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&response).unwrap()["id"],
            1
        );

        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn installer_wrapper_rejects_unknown_command() {
        let error = run_cbm_installer_command("config", &[]).unwrap_err();
        assert_eq!(error.envelope().code, "ASTRO_CBM_INSTALLER_COMMAND");
    }

    #[test]
    fn panic_callback_is_mapped_without_unwinding() {
        let err = catch_unwind_to_envelope(|| panic!("boom")).unwrap_err();
        assert_eq!(err.envelope().code, "ASTRO_FFI_CALLBACK_PANIC");
        assert_eq!(
            guard_ffi_callback(|| Err(envelope("ASTRO_TEST", "no", "fix"))),
            CALLBACK_ERROR
        );
        assert_eq!(guard_ffi_callback(|| panic!("boom")), CALLBACK_PANIC);
        assert_eq!(guard_ffi_callback(|| Ok(())), CALLBACK_OK);
    }

    #[test]
    fn row_sink_callback_guards_map_null_error_and_panic() {
        let node = cbm_sys::cbm_gbuf_row_node_t {
            id: 1,
            project: c"demo".as_ptr(),
            label: c"Function".as_ptr(),
            name: c"handler".as_ptr(),
            qualified_name: c"demo.handler".as_ptr(),
            file_path: c"src/main.rs".as_ptr(),
            start_line: 1,
            end_line: 3,
            properties_json: c"{}".as_ptr(),
        };
        assert_eq!(
            unsafe {
                guard_row_sink_node_callback(&node, |row| {
                    assert_eq!(row.id, 1);
                    Ok(())
                })
            },
            CALLBACK_OK
        );
        assert_eq!(
            unsafe { guard_row_sink_node_callback(std::ptr::null(), |_| Ok(())) },
            CALLBACK_ERROR
        );
        assert_eq!(
            unsafe {
                guard_row_sink_node_callback(&node, |_| -> Result<(), BridgeError> {
                    panic!("row sink panic")
                })
            },
            CALLBACK_PANIC
        );

        let edge = cbm_sys::cbm_gbuf_row_edge_t {
            id: 1,
            project: c"demo".as_ptr(),
            source_id: 1,
            target_id: 2,
            type_: c"IMPORTS".as_ptr(),
            properties_json: c"{\"local_name\":\"alpha\"}".as_ptr(),
            url_path_gen: c"".as_ptr(),
            local_name_gen: c"alpha".as_ptr(),
        };
        assert_eq!(
            unsafe {
                guard_row_sink_edge_callback(&edge, |row| {
                    let local_name = CStr::from_ptr(row.local_name_gen);
                    assert_eq!(local_name, c"alpha");
                    Ok(())
                })
            },
            CALLBACK_OK
        );
        assert_eq!(
            unsafe { guard_row_sink_edge_callback(std::ptr::null(), |_| Ok(())) },
            CALLBACK_ERROR
        );
    }

    #[test]
    fn row_sink_state_rejects_callback_thread_drift() {
        let mut state = PipelineRowSinkState::new();
        let ctx = (&mut state as *mut PipelineRowSinkState) as usize;
        let rc = std::thread::spawn(move || {
            let node = cbm_sys::cbm_gbuf_row_node_t {
                id: 1,
                project: c"demo".as_ptr(),
                label: c"Function".as_ptr(),
                name: c"handler".as_ptr(),
                qualified_name: c"demo.handler".as_ptr(),
                file_path: c"src/main.rs".as_ptr(),
                start_line: 1,
                end_line: 3,
                properties_json: c"{}".as_ptr(),
            };
            unsafe { pipeline_node_sink(&node, ctx as *mut c_void) }
        })
        .join()
        .expect("thread drift probe returns");

        assert_eq!(rc, CALLBACK_ERROR);
        assert!(state.nodes.is_empty());
        let error = state.error.take().expect("thread drift is recorded");
        assert_eq!(error.envelope().code, "ASTRO_CBM_ROW_SINK_THREAD");
    }

    #[test]
    fn watcher_callback_owner_keeps_raw_pointer_stable_and_reports_error() {
        let mut calls = 0;
        let owner = WatcherCallbackOwner::new(Box::new(move |project, root| {
            calls += 1;
            if calls == 1 {
                Ok(())
            } else {
                Err(envelope(
                    "ASTRO_WATCH_TEST_ERROR",
                    format!("{project}:{root}"),
                    "test remediation",
                ))
            }
        }));
        let user_data = owner.user_data();
        let mut moved_owner = move_watcher_callback_owner(owner);
        assert_eq!(moved_owner.user_data(), user_data);

        moved_owner.clear_last_error();
        let project = CString::new("demo").unwrap();
        let root = CString::new("C:/code/demo").unwrap();
        // SAFETY: strings and user_data remain live for this synchronous call.
        let success =
            unsafe { watcher_index_trampoline(project.as_ptr(), root.as_ptr(), user_data) };
        assert_eq!(success, CALLBACK_OK);
        assert!(moved_owner.take_last_error().is_none());

        moved_owner.clear_last_error();
        // SAFETY: strings and user_data remain live for this synchronous call.
        let error_status =
            unsafe { watcher_index_trampoline(project.as_ptr(), root.as_ptr(), user_data) };
        assert_eq!(error_status, CALLBACK_ERROR);
        let error = moved_owner
            .take_last_error()
            .expect("callback error is recorded through raw state");
        assert_eq!(error.envelope().code, "ASTRO_WATCH_TEST_ERROR");
        assert_eq!(error.envelope().message, "demo:C:/code/demo");
    }

    #[test]
    fn watcher_callback_owner_preserves_null_and_panic_mapping() {
        let mut null_owner = WatcherCallbackOwner::new(Box::new(|_, _| {
            panic!("NULL callback arguments must be rejected before invocation")
        }));
        let root = CString::new("C:/code/demo").unwrap();
        // SAFETY: user_data and root remain live; NULL is an intentional probe.
        let null_status =
            unsafe { watcher_index_trampoline(ptr::null(), root.as_ptr(), null_owner.user_data()) };
        assert_eq!(null_status, CALLBACK_ERROR);
        assert_eq!(
            null_owner
                .take_last_error()
                .expect("NULL argument error recorded")
                .envelope()
                .code,
            "ASTRO_CBM_NULL_CALLBACK_ARG"
        );

        let mut panic_owner =
            WatcherCallbackOwner::new(Box::new(|_, _| panic!("watcher callback panic probe")));
        let project = CString::new("demo").unwrap();
        // SAFETY: strings and user_data remain live for this synchronous call.
        let panic_status = unsafe {
            watcher_index_trampoline(project.as_ptr(), root.as_ptr(), panic_owner.user_data())
        };
        assert_eq!(panic_status, CALLBACK_PANIC);
        assert_eq!(
            panic_owner
                .take_last_error()
                .expect("panic error recorded")
                .envelope()
                .code,
            "ASTRO_FFI_CALLBACK_PANIC"
        );
    }

    #[test]
    fn watcher_callback_owner_drops_captured_state_exactly_once_after_move() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};

        struct DropProbe(Arc<AtomicUsize>);

        impl Drop for DropProbe {
            fn drop(&mut self) {
                self.0.fetch_add(1, Ordering::SeqCst);
            }
        }

        let drops = Arc::new(AtomicUsize::new(0));
        let probe = DropProbe(Arc::clone(&drops));
        let owner = WatcherCallbackOwner::new(Box::new(move |_, _| {
            let _keep_probe_captured = &probe;
            Ok(())
        }));
        let user_data = owner.user_data();
        let moved_owner = move_watcher_callback_owner(owner);
        assert_eq!(moved_owner.user_data(), user_data);
        assert_eq!(drops.load(Ordering::SeqCst), 0);

        drop(moved_owner);
        assert_eq!(drops.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn watcher_poll_interval_uses_cbm_adaptive_bounds() {
        assert_eq!(CbmWatcher::poll_interval_ms(0), 5000);
        assert_eq!(CbmWatcher::poll_interval_ms(1000), 7000);
        assert_eq!(CbmWatcher::poll_interval_ms(100000), 60000);
    }

    #[test]
    fn watcher_rejects_inputs_cbm_would_silently_ignore() {
        let mut watcher = CbmWatcher::new_for_polling(|_, _| Ok(())).unwrap();
        assert_eq!(
            watcher
                .watch("bad/name", "/tmp/astrolabe-watcher-inputs")
                .unwrap_err()
                .envelope()
                .code,
            "ASTRO_CBM_INVALID_PROJECT_NAME"
        );
        let injection_paths = [
            "/tmp/astrolabe;watcher",
            "/tmp/astrolabe|watcher",
            "/tmp/astrolabe&watcher",
            "/tmp/$(whoami)",
            "/tmp/`id`",
            "/tmp/astrolabe\nwatcher",
            "/tmp/astrolabe\"watcher",
            "/tmp/astrolabe>out",
            "' ; rm -rf / ; echo '",
        ];
        for path in injection_paths {
            assert_eq!(
                watcher
                    .watch("safe-name", path)
                    .unwrap_err()
                    .envelope()
                    .code,
                "ASTRO_CBM_UNSAFE_SHELL_ARG",
                "path should be rejected: {path:?}"
            );
        }
        // Windows-only cmd.exe expansion channels (audit #136): _popen runs
        // `cmd.exe /c` where %VAR% expands inside double quotes, %X:~n,m%
        // substring forms can materialize quotes, `^` escapes the next
        // character, and !VAR! is delayed expansion.
        #[cfg(windows)]
        {
            let cmd_expansion_paths = [
                "C:/repos/%USERPROFILE%",
                "C:/repos/%PATH:~0,1%evil",
                "C:/repos/astrolabe^watcher",
                "C:/repos/!TEMP!",
            ];
            for path in cmd_expansion_paths {
                assert_eq!(
                    watcher
                        .watch("safe-name", path)
                        .unwrap_err()
                        .envelope()
                        .code,
                    "ASTRO_CBM_UNSAFE_SHELL_ARG",
                    "cmd.exe expansion path should be rejected: {path:?}"
                );
            }
        }
        assert_eq!(watcher.watch_count().unwrap(), 0);
    }

    #[test]
    fn tool_runner_maps_is_error_envelope() {
        let runner = CbmToolRunner::new(":memory:").unwrap();
        let err = runner.handle_tool("not_a_tool", "{}").unwrap_err();
        assert_eq!(err.envelope().code, "ASTRO_CBM_TOOL_ERROR");
        assert!(err.envelope().message.contains("unknown tool"));
        assert!(err.envelope().stderr.is_some());
    }

    #[test]
    fn tool_runner_create_use_drop_repeatedly() {
        for _ in 0..1000 {
            let runner = CbmToolRunner::new(":memory:").unwrap();
            let err = runner.handle_tool("not_a_tool", "{}").unwrap_err();
            assert_eq!(err.envelope().code, "ASTRO_CBM_TOOL_ERROR");
        }
    }
}
