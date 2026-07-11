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

pub fn cbm_cache_dir() -> Result<PathBuf, BridgeError> {
    cbm_sys::initialize_allocator_bindings_first();
    let ptr = unsafe { cbm_sys::cbm_resolve_cache_dir() };
    if ptr.is_null() {
        return Err(envelope(
            "ASTRO_CBM_CACHE_DIR",
            "CBM could not resolve its cache directory",
            "Set CBM_CACHE_DIR or HOME/LOCALAPPDATA to a writable directory.",
        ));
    }
    Ok(PathBuf::from(unsafe { CStr::from_ptr(ptr) }.to_str()?))
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

#[cfg(not(unix))]
pub fn parent_process_id() -> Option<u32> {
    None
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

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CbmIndexRepositoryRows {
    pub raw_json: String,
    pub rows: CbmPipelineRows,
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
        if let Some(error) = sink.error {
            return Err(error);
        }
        let project = project_from_tool_result(&raw_json)
            .or_else(|| sink.nodes.first().map(|node| node.project.clone()))
            .or_else(|| sink.edges.first().map(|edge| edge.project.clone()))
            .unwrap_or_default();
        Ok(CbmIndexRepositoryRows {
            raw_json,
            rows: CbmPipelineRows {
                project,
                nodes: sink.nodes,
                edges: sink.edges,
            },
        })
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
        let dir = temp_dir("tool-runner-row-sink");
        let repo = dir.join("repo");
        let src = repo.join("src");
        std::fs::create_dir_all(&src).expect("create fixture repo");
        std::fs::write(
            src.join("main.c"),
            "int helper(void) { return 41; }\nint main(void) { return helper() + 1; }\n",
        )
        .expect("write C fixture");
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        let project = format!("row-sink-tool-{}-{nanos}", std::process::id());
        let args = serde_json::json!({
            "repo_path": repo.to_str().expect("utf8 repo path"),
            "mode": "full",
            "name": project,
        })
        .to_string();

        // Fail-closed teardown: delete the registered project .db even if any
        // assertion below panics, so this test never leaks a registration into the
        // operator's global CBM store (#194).
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
        assert_eq!(run.rows.project, project);
        assert!(
            run.rows
                .nodes
                .iter()
                .any(|node| node.qualified_name.ends_with(".main")),
            "expected main function in MCP row sink: {:?}",
            run.rows
        );
        assert!(
            run.rows
                .nodes
                .iter()
                .all(|node| node.project == run.rows.project)
        );
        assert!(
            run.rows
                .edges
                .iter()
                .all(|edge| edge.project == run.rows.project)
        );

        // `_db_guard` deletes the registration on scope exit (fail-closed).
        std::fs::remove_dir_all(dir).ok();
    }

    /// Regression for #194: prove — by reading the persisted `.db` file on disk
    /// (full state verification, not a return value) — that a tool-runner
    /// `index_repository` run registers exactly one project db in the resolved CBM
    /// cache dir and that teardown removes it, leaving zero store residue.
    #[test]
    fn tool_runner_index_repository_leaves_no_store_residue() {
        let dir = temp_dir("tool-runner-residue");
        let repo = dir.join("repo");
        let src = repo.join("src");
        std::fs::create_dir_all(&src).expect("create fixture repo");
        std::fs::write(
            src.join("main.c"),
            "int helper(void) { return 41; }\nint main(void) { return helper() + 1; }\n",
        )
        .expect("write C fixture");
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system time after epoch")
            .as_nanos();
        let project = format!("row-sink-residue-{}-{nanos}", std::process::id());
        let args = serde_json::json!({
            "repo_path": repo.to_str().expect("utf8 repo path"),
            "mode": "full",
            "name": project,
        })
        .to_string();

        let cache_dir = cbm_cache_dir().expect("resolve CBM cache dir");
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
            assert_eq!(run.rows.project, project);
            // Mid-run source-of-truth read: the registration exists on disk.
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
        std::fs::remove_dir_all(dir).ok();
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
