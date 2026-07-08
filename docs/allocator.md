# Allocator Unification

Astrolabe uses the mimalloc source vendored by `vendor/codebase-memory-mcp` as the single production allocator implementation for the CBM and Rust halves.

`libcbm.a` keeps raw `mi_*` symbols local. The Astrolabe overlay exports only `cbm_mimalloc_*` shims from `patches/cbm/astro_alloc_shim.c`; `cbm-sys` implements Rust's `#[global_allocator]` by calling those shims. This avoids pulling in the Rust `mimalloc` crate or any second mimalloc source tree.

Startup code that can call libcbm must call `cbm_sys::initialize_allocator_bindings_first()` before other libcbm entry points. The bridge constructors do this before `cbm_init`, extraction, or MCP server creation. The function calls `cbm_alloc_init()` and asserts that the runtime mimalloc version matches the vendored header version captured by `cbm-sys/build.rs`.

ASan builds set `CBM_SYS_ASAN=1`. In that profile, `cbm-sys` does not install the Rust mimalloc global allocator, and the libcbm overlay compiles mimalloc without allocator override or tree-sitter/SQLite allocator binding. Mimalloc remains linked only for process RSS APIs and shim/version checks, so ASan still owns ordinary Rust and C allocation interception.

`scripts/check-single-mimalloc.sh` scans an Astrolabe test binary and fails unless it finds exactly one raw mimalloc implementation plus one `cbm_mimalloc_*` shim surface.
