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
