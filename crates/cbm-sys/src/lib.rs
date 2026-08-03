#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unsafe_op_in_unsafe_fn)]

#[cfg(not(cbm_sys_asan))]
use std::alloc::{GlobalAlloc, Layout};
#[cfg(not(cbm_sys_asan))]
use std::ffi::c_void;
use std::ffi::{CStr, CString};
use std::path::Path;
use std::ptr;

pub const CRATE_NAME: &str = env!("CARGO_PKG_NAME");
pub const CBM_VENDOR_ROOT: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/../../cbm");
pub const VENDORED_MIMALLOC_VERSION: &str = env!("CBM_MIMALLOC_VERSION");

include!("bindings.rs");

#[cfg(not(cbm_sys_asan))]
#[global_allocator]
static ASTROLABE_MIMALLOC: CbmMiMalloc = CbmMiMalloc;

#[cfg(not(cbm_sys_asan))]
pub struct CbmMiMalloc;

#[cfg(not(cbm_sys_asan))]
unsafe impl GlobalAlloc for CbmMiMalloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let size = layout.size().max(1);
        unsafe { cbm_mimalloc_malloc_aligned(size, layout.align()).cast::<u8>() }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let size = layout.size().max(1);
        unsafe { cbm_mimalloc_zalloc_aligned(size, layout.align()).cast::<u8>() }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        unsafe {
            cbm_mimalloc_free(ptr.cast::<c_void>());
        }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        let size = new_size.max(1);
        unsafe { cbm_mimalloc_realloc_aligned(ptr.cast::<c_void>(), size, layout.align()).cast() }
    }
}

#[derive(Debug, Clone, Copy, Default, Eq, PartialEq)]
pub struct MiProcessInfo {
    pub elapsed_msecs: usize,
    pub user_msecs: usize,
    pub system_msecs: usize,
    pub current_rss: usize,
    pub peak_rss: usize,
    pub current_commit: usize,
    pub peak_commit: usize,
    pub page_faults: usize,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CbmStoreCount {
    pub name: String,
    pub count: i32,
}

#[derive(Debug, Clone, Eq, PartialEq)]
pub struct CbmStoreQuerySchemaCounts {
    pub search_count: i32,
    pub search_total: i32,
    pub node_labels: Vec<CbmStoreCount>,
    pub edge_types: Vec<CbmStoreCount>,
}

pub fn vendor_root() -> &'static str {
    CBM_VENDOR_ROOT
}

pub fn vendored_mimalloc_version() -> i32 {
    VENDORED_MIMALLOC_VERSION
        .parse()
        .expect("CBM_MIMALLOC_VERSION must be an integer")
}

pub fn mimalloc_version() -> i32 {
    unsafe { cbm_mimalloc_version() }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CbmAllocatorInitError {
    pub code: &'static str,
    pub message: String,
    pub remediation: &'static str,
    pub sqlite_error: Option<i32>,
}

impl std::fmt::Display for CbmAllocatorInitError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "{}: {} (remediation: {})",
            self.code, self.message, self.remediation
        )
    }
}

impl std::error::Error for CbmAllocatorInitError {}

pub fn initialize_allocator_bindings_first() -> Result<(), CbmAllocatorInitError> {
    let status = unsafe { cbm_alloc_init() };
    if status != 0 {
        return Err(CbmAllocatorInitError {
            code: "CBM_SQLITE_ALLOCATOR_BIND_FAILED",
            message: format!(
                "libcbm rejected allocator initialization with SQLite status {status}"
            ),
            remediation: "initialize libcbm before every other SQLite or tree-sitter call, then restart the process",
            sqlite_error: Some(status),
        });
    }
    let observed = mimalloc_version();
    let expected = vendored_mimalloc_version();
    if observed != expected {
        return Err(CbmAllocatorInitError {
            code: "CBM_MIMALLOC_VERSION_MISMATCH",
            message: format!(
                "the linked C allocator version {observed} does not match the Rust allocator version {expected}"
            ),
            remediation: "rebuild both Rust and libcbm with the repository-pinned native Windows GNU toolchain",
            sqlite_error: None,
        });
    }
    Ok(())
}

/// Reads back libcbm's allocator-binding flag (#5).
///
/// Returns `true` once [`initialize_allocator_bindings_first`] (via
/// `cbm_alloc_init`) has bound SQLite to the shared mimalloc heap and
/// Tree-sitter to CBM's slab allocator. This is only observable in a build that
/// enables the binding (`CBM_BIND_TS_ALLOCATOR` — the linked `libcbm.a` and the
/// production binary); the vendored test build leaves it `false` because the
/// binding is a deliberate no-op there. Startup code uses it as a deterministic
/// init-order probe: SQLite and Tree-sitter must never allocate before this
/// reads `true`.
pub fn allocator_bindings_active() -> bool {
    unsafe { cbm_alloc_bindings_active() != 0 }
}

pub fn mimalloc_collect(force: bool) {
    unsafe {
        cbm_mimalloc_collect(force);
    }
}

pub fn mimalloc_process_info() -> MiProcessInfo {
    let mut info = MiProcessInfo::default();
    unsafe {
        cbm_mimalloc_process_info(
            &mut info.elapsed_msecs,
            &mut info.user_msecs,
            &mut info.system_msecs,
            &mut info.current_rss,
            &mut info.peak_rss,
            &mut info.current_commit,
            &mut info.peak_commit,
            &mut info.page_faults,
        );
    }
    info
}

pub fn query_store_search_schema_counts(
    db_path: &Path,
    project: &str,
    label: &str,
) -> Result<CbmStoreQuerySchemaCounts, String> {
    initialize_allocator_bindings_first().map_err(|error| error.to_string())?;
    let db_path = CString::new(
        db_path
            .to_str()
            .ok_or_else(|| "CBM store path is not valid UTF-8".to_string())?,
    )
    .map_err(|error| format!("CBM store path contains NUL byte: {error}"))?;
    let project =
        CString::new(project).map_err(|error| format!("project contains NUL byte: {error}"))?;
    let label = CString::new(label).map_err(|error| format!("label contains NUL byte: {error}"))?;
    let sort_by = CString::new("name").expect("static sort key has no NUL byte");

    unsafe {
        let mut verification = cbm_store_verify_result_t::default();
        let mut store = ptr::null_mut();
        let status = cbm_store_open_path_project_query_verified(
            db_path.as_ptr(),
            project.as_ptr(),
            &mut store,
            &mut verification,
        );
        if status != cbm_store_verify_status_t_CBM_STORE_VERIFY_OK || store.is_null() {
            let mut close_error = None;
            if !store.is_null() {
                close_error = close_store_exact(&mut store).err();
            }
            let code = if status == cbm_store_verify_status_t_CBM_STORE_VERIFY_INTEGRITY_FAILED {
                "CBM_STORE_INTEGRITY_FAILED"
            } else if status == cbm_store_verify_status_t_CBM_STORE_VERIFY_SOURCE_MISSING {
                "CBM_STORE_SOURCE_MISSING"
            } else {
                "CBM_STORE_VERIFICATION_FAILED"
            };
            let verification_error = format!(
                "code={code} status={status} operation={} native_error={} sqlite_error={} detail={} remediation=preserve the database, WAL, and SHM together; resolve the reported failure, then retry",
                c_char_array(&verification.operation),
                verification.native_error,
                verification.sqlite_error,
                c_char_array(&verification.detail),
            );
            return Err(match close_error {
                Some(close_error) => format!("{verification_error}; close_error={close_error}"),
                None => verification_error,
            });
        }

        let result = query_open_store_search_schema_counts(store, &project, &label, &sort_by);
        let close_result = close_store_exact(&mut store);
        match (result, close_result) {
            (Ok(value), Ok(())) => Ok(value),
            (Err(error), Ok(())) => Err(error),
            (Ok(_), Err(close_error)) => Err(close_error),
            (Err(error), Err(close_error)) => {
                Err(format!("query_error={error}; close_error={close_error}"))
            }
        }
    }
}

unsafe fn close_store_exact(store: &mut *mut cbm_store_t) -> Result<(), String> {
    let mut result = cbm_store_close_result_t::default();
    let status = unsafe { cbm_store_close(store, &mut result) };
    if status == CBM_STORE_CLOSE_OK && (*store).is_null() {
        return Ok(());
    }
    if result.connection_destroyed == 0 || !(*store).is_null() {
        eprintln!(
            "code=CBM_STORE_CLOSE_LIVE_OWNER_UNRETURNABLE status={} sqlite_error={} outstanding_statements={} first_sql_sha256={} db_path={}",
            result.status,
            result.sqlite_close_code,
            result.outstanding_statement_count,
            c_char_array(&result.first_outstanding_sql_sha256),
            c_char_array(&result.db_path),
        );
        std::process::abort();
    }
    Err(format!(
        "code=CBM_STORE_CLOSE_FAILED status={} sqlite_error={} connection_destroyed={} outstanding_statements={} first_sql_sha256={} db_path={} remediation=preserve the exact store owner and complete the reported SQLite resource before retrying",
        result.status,
        result.sqlite_close_code,
        result.connection_destroyed,
        result.outstanding_statement_count,
        c_char_array(&result.first_outstanding_sql_sha256),
        c_char_array(&result.db_path),
    ))
}

fn c_char_array<const N: usize>(value: &[std::os::raw::c_char; N]) -> String {
    // The C verifier always NUL-terminates these fixed-capacity diagnostics.
    unsafe { CStr::from_ptr(value.as_ptr()) }
        .to_string_lossy()
        .into_owned()
}

unsafe fn query_open_store_search_schema_counts(
    store: *mut cbm_store_t,
    project: &CString,
    label: &CString,
    sort_by: &CString,
) -> Result<CbmStoreQuerySchemaCounts, String> {
    let params = cbm_search_params_t {
        project: project.as_ptr(),
        label: label.as_ptr(),
        name_pattern: ptr::null(),
        qn_pattern: ptr::null(),
        file_pattern: ptr::null(),
        relationship: ptr::null(),
        direction: ptr::null(),
        min_degree: -1,
        max_degree: -1,
        limit: 10,
        offset: 0,
        exclude_entry_points: false,
        include_connected: true,
        sort_by: sort_by.as_ptr(),
        case_sensitive: true,
        exclude_labels: ptr::null_mut(),
    };
    let mut search = cbm_search_output_t::default();
    let rc = unsafe { cbm_store_search(store, &params, &mut search) };
    if rc != CBM_STORE_OK as i32 {
        return Err(format!(
            "CBM store search failed with rc={rc}: {}",
            unsafe { store_error_message(store) }
        ));
    }
    let search_count = search.count;
    let search_total = search.total;
    unsafe {
        cbm_store_search_free(&mut search);
    }

    let mut schema = cbm_schema_info_t::default();
    let rc = unsafe { cbm_store_get_schema_counts(store, project.as_ptr(), &mut schema) };
    if rc != CBM_STORE_OK as i32 {
        return Err(format!(
            "CBM schema counts failed with rc={rc}: {}",
            unsafe { store_error_message(store) }
        ));
    }
    let node_labels = unsafe { collect_label_counts(&schema) };
    let edge_types = unsafe { collect_edge_type_counts(&schema) };
    unsafe {
        cbm_store_schema_free(&mut schema);
    }

    Ok(CbmStoreQuerySchemaCounts {
        search_count,
        search_total,
        node_labels: node_labels?,
        edge_types: edge_types?,
    })
}

unsafe fn collect_label_counts(schema: &cbm_schema_info_t) -> Result<Vec<CbmStoreCount>, String> {
    let count = schema_count_len(schema.node_label_count, "node label count")?;
    if count == 0 {
        return Ok(Vec::new());
    }
    if schema.node_labels.is_null() {
        return Err("CBM schema returned NULL node labels with non-zero count".to_string());
    }

    let labels = unsafe { std::slice::from_raw_parts(schema.node_labels, count) };
    labels
        .iter()
        .map(|row| {
            Ok(CbmStoreCount {
                name: unsafe { c_string(row.label, "node label") }?,
                count: row.count,
            })
        })
        .collect()
}

unsafe fn collect_edge_type_counts(
    schema: &cbm_schema_info_t,
) -> Result<Vec<CbmStoreCount>, String> {
    let count = schema_count_len(schema.edge_type_count, "edge type count")?;
    if count == 0 {
        return Ok(Vec::new());
    }
    if schema.edge_types.is_null() {
        return Err("CBM schema returned NULL edge types with non-zero count".to_string());
    }

    let types = unsafe { std::slice::from_raw_parts(schema.edge_types, count) };
    types
        .iter()
        .map(|row| {
            Ok(CbmStoreCount {
                name: unsafe { c_string(row.type_, "edge type") }?,
                count: row.count,
            })
        })
        .collect()
}

fn schema_count_len(count: i32, field: &str) -> Result<usize, String> {
    usize::try_from(count).map_err(|_| format!("CBM schema returned negative {field}: {count}"))
}

unsafe fn c_string(ptr: *const std::os::raw::c_char, field: &str) -> Result<String, String> {
    if ptr.is_null() {
        return Err(format!("CBM schema returned NULL {field}"));
    }
    Ok(unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned())
}

unsafe fn store_error_message(store: *mut cbm_store_t) -> String {
    let ptr = unsafe { cbm_store_error(store) };
    if ptr.is_null() {
        return "no error detail".to_string();
    }
    unsafe { CStr::from_ptr(ptr) }
        .to_string_lossy()
        .into_owned()
}
