# Allocator Topology

Astrolabe links exactly one mimalloc implementation: the source vendored by
`vendor/codebase-memory-mcp`. This is an implementation-identity invariant, not
a claim that every allocation on every platform belongs to one heap.

Production routing is platform-specific:

- Rust installs a `#[global_allocator]` that delegates to the exported
  `cbm_mimalloc_*` shims in `patches/cbm/astro_alloc_shim.c`.
- `cbm_alloc_init()` binds tree-sitter and SQLite to that mimalloc instance
  before either subsystem initializes.
- MinGW uses `MI_MALLOC_OVERRIDE=1` with the static CRT, so ordinary CBM C/CRT
  allocation is routed through mimalloc there.
- Linux and macOS do not enable the global override. Ordinary CBM C allocations
  continue to use libc because overriding process `malloc`/`free` caused invalid
  cross-library frees on macOS. `mi_process_info` heap/commit counters do not
  account for those libc allocations, and its platform-dependent RSS fields do
  not prove one-heap routing. Process-wide pressure uses `cbm_mem_rss()` with OS
  RSS as the Linux primary source and the cross-platform fallback.

Ownership remains explicit even where allocators happen to coincide. Rust-owned
memory is released by Rust. CBM-owned strings and buffers crossing FFI are
released through their CBM deallocator; callers never substitute libc or Rust
deallocation based on an assumed shared heap.

Startup code that can call libcbm must call
`cbm_sys::initialize_allocator_bindings_first()` before other libcbm entry
points. Bridge constructors do this before `cbm_init`, extraction, or MCP server
creation. The function calls `cbm_alloc_init()` and asserts that the runtime
mimalloc version matches the vendored header version captured by
`cbm-sys/build.rs`.

ASan builds set `CBM_SYS_ASAN=1`. In that profile, `cbm-sys` does not install the
Rust mimalloc global allocator, and the libcbm overlay compiles mimalloc without
allocator override or tree-sitter/SQLite allocator binding. Mimalloc remains
linked only for process APIs and shim/version checks, so ASan owns ordinary Rust
and C allocation interception.

`scripts/check-single-mimalloc.sh` verifies that a final Astrolabe test binary
contains exactly one raw mimalloc implementation and one `cbm_mimalloc_*` shim
surface. `scripts/check-allocator-contract.py` verifies the platform routing,
Rust shim, initialization binding, dependency, documentation, and gate contract.
