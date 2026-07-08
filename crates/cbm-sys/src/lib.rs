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
pub const CBM_VENDOR_ROOT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../vendor/codebase-memory-mcp"
);
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

pub fn assert_mimalloc_version_matches_vendored() {
    assert_eq!(
        mimalloc_version(),
        vendored_mimalloc_version(),
        "Rust and C halves must use the vendored mimalloc version"
    );
}

pub fn initialize_allocator_bindings_first() {
    unsafe {
        cbm_alloc_init();
    }
    assert_mimalloc_version_matches_vendored();
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
    initialize_allocator_bindings_first();
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
        let store = cbm_store_open_path_query(db_path.as_ptr());
        if store.is_null() {
            return Err("CBM store open returned NULL".to_string());
        }

        let result = query_open_store_search_schema_counts(store, &project, &label, &sort_by);
        cbm_store_close(store);
        result
    }
}

unsafe fn query_open_store_search_schema_counts(
    store: *mut cbm_store_t,
    project: &CString,
    label: &CString,
    sort_by: &CString,
) -> Result<CbmStoreQuerySchemaCounts, String> {
    if unsafe { !cbm_store_check_integrity(store) } {
        return Err(format!("CBM store integrity check failed: {}", unsafe {
            store_error_message(store)
        }));
    }

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::ptr::NonNull;

    #[test]
    fn exposes_cbm_vendor_root() {
        assert!(vendor_root().ends_with("vendor/codebase-memory-mcp"));
    }

    #[test]
    fn mimalloc_version_matches_vendored_header() {
        initialize_allocator_bindings_first();
        assert_mimalloc_version_matches_vendored();
    }

    #[cfg(not(cbm_sys_asan))]
    #[test]
    fn rust_and_c_allocations_share_mimalloc_accounting() {
        initialize_allocator_bindings_first();
        mimalloc_collect(true);
        let before = mimalloc_process_info();

        const ALLOC_SIZE: usize = 32 * 1024 * 1024;
        let mut rust_buffer = vec![0xA5_u8; ALLOC_SIZE];
        let rust_usable =
            unsafe { cbm_mimalloc_usable_size(rust_buffer.as_ptr().cast::<c_void>()) };
        assert!(
            rust_usable >= ALLOC_SIZE,
            "Rust allocation was not owned by the vendored mimalloc heap"
        );
        let after_rust = mimalloc_process_info();

        let c_ptr = NonNull::new(unsafe { cbm_mimalloc_malloc(ALLOC_SIZE).cast::<u8>() })
            .expect("cbm_mimalloc_malloc returned NULL");
        unsafe {
            std::ptr::write_bytes(c_ptr.as_ptr(), 0x5A, ALLOC_SIZE);
        }
        let c_usable = unsafe { cbm_mimalloc_usable_size(c_ptr.as_ptr().cast::<c_void>()) };
        assert!(
            c_usable >= ALLOC_SIZE,
            "C allocation was not owned by the vendored mimalloc heap"
        );
        let after_both = mimalloc_process_info();

        assert!(
            after_rust.current_commit > before.current_commit
                || after_rust.current_rss > before.current_rss,
            "Rust allocation was not reflected by mi_process_info: before={before:?} after={after_rust:?}"
        );
        assert!(
            after_both.current_commit > after_rust.current_commit
                || after_both.current_rss > after_rust.current_rss,
            "C allocation was not reflected by mi_process_info: rust={after_rust:?} both={after_both:?}"
        );

        unsafe {
            cbm_mimalloc_free(c_ptr.as_ptr().cast::<c_void>());
        }
        rust_buffer.fill(0);
        drop(rust_buffer);
        mimalloc_collect(true);
    }
}
