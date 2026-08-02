# Allocator Topology

Astrolabe links exactly one mimalloc implementation: the source under
`cbm/`. This is an implementation-identity invariant, not
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

## Initialization order

Startup code that can call libcbm must call
`cbm_sys::initialize_allocator_bindings_first()` before other libcbm entry
points. Bridge constructors do this before `cbm_init`, extraction, or MCP server
creation. The function calls `cbm_alloc_init()` and asserts that the runtime
mimalloc version matches the vendored header version captured by
`cbm-sys/build.rs`.

`cbm_alloc_init()` binds SQLite via `SQLITE_CONFIG_MALLOC`, which SQLite ignores
with `SQLITE_MISUSE` once it has initialized. Calling any store entry point
before the binding would therefore leave SQLite on its own allocator, so the
ordering is a correctness contract, not an optimization. Two mechanisms enforce
it: the C-side `assert(sqlite_rc == SQLITE_OK)` inside `cbm_alloc_init()` aborts
fail-closed if SQLite initialized first, and `cbm_alloc_bindings_active()`
(Rust: `cbm_sys::allocator_bindings_active()`) reads the binding flag back so a
manual Full State Verification can prove the binding is live *before* it opens a
store.

## MinGW-only global override

The static-CRT `malloc`/`free` override (`-DMI_MALLOC_OVERRIDE=1`, mimalloc
3.3.0's `_MSC_VER` / `_ACRTIMP` / `_CRT_HYBRIDPATCHABLE` entry points) is enabled
**only** when `patches/cbm/Makefile.cbm` detects a MinGW target
(`IS_MINGW = yes`, from the compiler's own `_WIN32` predefine). Unix builds never
receive the define — overriding process `malloc`/`free` there caused invalid
cross-library frees on macOS (see the Unix routing note above). This is a
build-time platform gate: the same `MIMALLOC_OVERRIDE_DEFINE` value flows into
`libcbm.a`, `cbm`, and `cbm-with-ui`, so no artifact can diverge from it.

## Sanitizer strategy

ASan builds set `CBM_SYS_ASAN=1`. In that profile, `cbm-sys` does not install the
Rust mimalloc global allocator, and the libcbm overlay compiles mimalloc without
allocator override or tree-sitter/SQLite allocator binding (`LIBCBM_ASAN=1` drops
`CBM_BIND_TS_ALLOCATOR`, so `cbm_alloc_bindings_active()` stays `0` by design).
Mimalloc remains linked only for process APIs and shim/version checks, so ASan
owns ordinary Rust and C allocation interception. The allocator-topology tests
that assume the mimalloc global allocator are `#[cfg(not(cbm_sys_asan))]`.

ASan is a sanitizer-on-Linux facility. The Windows-only directive that formerly
deferred it (`DEFERRED[ASTRO_PORT_PHASE]`, #238) is withdrawn as of 2026-08-01, so
this is now an ordinary open gap rather than a scoped-out deferral. The wiring
above is present and compiled, so executing an ASan build is a scheduling choice,
not a missing capability. Note that macOS/Apple Silicon has no direct equivalent
of the Linux ASan configuration described here; if ASan execution is wanted on
this host it needs its own issue naming the Darwin approach.

## Topology verification (FSV)

The former `scripts/check-single-mimalloc.sh` and
`scripts/check-allocator-contract.py` gate scripts were removed with the rest of
the aggregate gate suite under the 2026-07-13 FSV-only directive; they are not
rebuilt. The single-implementation invariant is verified instead by reading the
symbol table of the built artifact directly. On the native Windows-GNU archive:

```sh
# Exactly one mimalloc implementation is linked (one defining `mi_malloc`):
nm target/**/build/*/out/cbm-build/libcbm.a | grep -E ' T _?mi_malloc$' | wc -l   # => 1
# Exactly one cbm_mimalloc_* shim surface (the Rust global allocator's C seam):
nm target/**/build/*/out/cbm-build/libcbm.a | grep -E ' T _?cbm_mimalloc_free$' | wc -l  # => 1
```

The behavioral half of the topology invariant — Rust and C allocations sharing
one heap, cross-heap alloc/free across the FFI seam, and SQLite/tree-sitter
riding the same heap — is proven by the native `cbm-sys` tests
`rust_and_c_allocations_share_mimalloc_accounting`,
`cross_heap_alloc_and_free_through_ffi_seam`, and
`cbm_alloc_init_binds_before_sqlite_use`.
