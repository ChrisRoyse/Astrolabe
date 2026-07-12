# CBM Patch Policy

`vendor/codebase-memory-mcp` is the unmodified parent source for issue #1. Do
not patch files in that subtree directly for integration work.

If Astrolabe needs a CBM change before it can be upstreamed, add a patch file in
this directory and document:

- the CBM file or behavior it changes;
- the Astrolabe issue that requires it;
- the verification command proving the patched behavior;
- whether the patch is temporary or intended for upstream.

## #149: pressure-log percentage buffers

`apply_mem_pressure_patch.py` generates a build-local overlay of
`src/foundation/mem.c` that expands only the two `size_t` percentage buffers
from `CBM_SZ_16` to `CBM_SZ_32`. `Makefile.cbm` compiles that generated overlay
for `libcbm.a`; it never writes into `vendor/codebase-memory-mcp`.

Verify with `python -B scripts/test-cbm-mem-pressure-patch.py` and a native
Windows-GNU `cargo test -p cbm-sys` run with `-Werror` enabled. This is a
temporary integration patch intended for upstreaming to CBM.

## #240 / #241: store resolution — explicit FFI config + fail-closed env reads

`env_store_config.{c,h}` are Astrolabe-owned C compiled into `libcbm.a`. They
provide (a) `cbm_astro_set_cache_dir()` — the store location passed across the
FFI boundary as a **parameter**, the only runtime-safe channel because Rust's
`std::env::set_var` writes the Win32 environment block while `cbm_safe_getenv`
reads the CRT `environ` array (they diverge on Windows); and (b) a fail-closed
`{code, message, remediation}` fault record for environment reads that would
truncate.

`env_apply_store_patch.py` generates hash-checked build-local overlays of five
pinned CBM sources so the vendored resolvers use those facilities:
`src/foundation/platform.c` (override consult + snprintf truncation detection +
widened env scratch buffers `CBM_SZ_256`→`CBM_SZ_1K` + named unresolvable-store
refusal), `src/pipeline/pipeline.c`, `src/cli/cli.c`, `src/mcp/mcp.c`,
`src/ui/http_server.c` (NULL-check every `cbm_resolve_cache_dir()` fed to
`snprintf("%s", ...)`). `Makefile.cbm` compiles the overlays and
`env_store_config.o` into `libcbm.a`; nothing under `vendor/` is written.

`scripts/check-cbm-env-contract.py` (a #240 lint gate) fails the build closed if
any Rust code calls `set_var`/`remove_var` on a libcbm-consumed variable — the
ban list is measured from the pinned CBM tree. Verify with:

- `python -B scripts/test-cbm-env-store-patch.py` (overlay hashes/edits/idempotence),
- `python -B scripts/test-cbm-env-contract.py` (lint gate is load-bearing),
- a native Windows-GNU `cargo test -p astrolabe-bridge` store-env run (FSV: the
  relocated store DB appears on disk; truncated/unresolvable env fails closed).

Temporary integration patches intended for upstreaming to CBM.
