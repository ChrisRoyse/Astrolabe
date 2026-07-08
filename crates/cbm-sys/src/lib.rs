#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(non_upper_case_globals)]
#![allow(unsafe_op_in_unsafe_fn)]

#[cfg(not(cbm_sys_asan))]
use std::alloc::{GlobalAlloc, Layout};
#[cfg(not(cbm_sys_asan))]
use std::ffi::c_void;

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
