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

## #227: shell-free git spawn (remove cmd.exe from CBM's git shell-outs)

CBM's git helpers composed a command STRING and handed it to `cbm_popen`, which
runs `cmd.exe /c <string>` on Windows (the CRT `_popen` "executes a spawned copy
of the command processor") and `/bin/sh -c <string>` on POSIX. cmd.exe performs
`%VAR%` / `%X:~n,m%` substitution and `^` escaping at PARSE time, before quoting
applies, so no quoting of an interpolated repo path can make the string inert —
each new metacharacter class becomes another blocklist entry in the validator.

- `astro_spawn.c` / `astro_spawn.h` — the Astrolabe-side, shell-free spawn
  helper `cbm_spawn_capture(argv[], out, len, err)`: `CreateProcessW` with an
  explicit, `CommandLineToArgvW`-exact quoted command line on Windows (and
  PATH-only executable resolution, never the CWD), `posix_spawnp` on POSIX, with
  the child's stdout captured via a pipe and stdin/stderr bound to the null
  device. Fail-closed `{code, message, remediation}` errors. Not a vendor edit.
- `astro_overlay.py` — shared hash-check + anchored-replace primitives used by
  the generators below (fail closed with expected/found digests on drift).
- `apply_spawn_git_context_patch.py`, `apply_spawn_artifact_patch.py`,
  `apply_spawn_watcher_patch.py`, `apply_spawn_githistory_patch.py` — build-local
  overlays of `src/git/git_context.c`, `src/pipeline/artifact.c`,
  `src/watcher/watcher.c`, and `src/pipeline/pass_githistory.c` that route every
  `cbm_popen` git call through `cbm_spawn_capture` with an argv array. Each pins
  the vendored source sha256 and writes into `$(LIBCBM_DIR)`; none touches
  `vendor/`. `Makefile.cbm` compiles the overlays plus `astro_spawn.c` into
  `libcbm.a`. The existing shell-arg validators stay as defence in depth.

Verify with `python -B scripts/test-cbm-spawn-patch.py` (patch-byte regression:
no `cbm_popen` remains on any git path; a reintroduced one is caught) and
`python -B scripts/test-cbm-spawn-fsv.py` (Full State Verification: builds a real
git repo whose path carries `%VAR%`, `!`, `^`, `;`, `&`, and spaces, then reads
back both the captured HEAD sha and the exact argv git received — proving no
shell expansion or splitting occurred). Temporary integration patch intended for
upstreaming to CBM.

## #228: `cbm_validate_shell_arg` rejects `%` `^` `!` under `_WIN32`

`apply_shellarg_str_util_patch.py` overlays `src/foundation/str_util.c` to add
the Windows `%`, `^`, `!` rejection the Rust bridge validator got in #136 (its
`#ifndef _WIN32` split previously covered only backslash). Defence in depth: with
#227 the git paths no longer use a shell at all, so this is no longer the sole
barrier, but the C mirror must not disagree with the Rust validator about which
byte classes are shell-unsafe. Covered by `scripts/test-cbm-spawn-patch.py`
(asserts the `_WIN32` case block gains `%`/`^`/`!` and the POSIX branch is
unchanged) and the CBM clang-format overlay gate. Intended for upstreaming.

## #229: cbm-with-ui -Werror overlays (native MinGW GCC 14.1)

The `cbm` and `cbm-with-ui` production binaries compile the vendored sources
**directly** (via `PROD_SRCS`), unlike `libcbm.a`, whose overlays live under
`$(LIBCBM_DIR)` — so the libcbm store/spawn overlays above do **not** reach the
production binaries. Three vendored sources trip GCC 14.1 `-Werror` on the native
Windows toolchain, blocking `cbm-with-ui` and therefore the #17 unmodified-UI
smoke gate:

- `src/pipeline/pass_envscan.c` — `-Wstringop-truncation` on the
  `strncpy(dst, src, sizeof-1)` + explicit-NUL idiom.
- `src/watcher/watcher.c` — `-Wstringop-truncation` on two
  `strncpy(s->last_head, head, sizeof-1)` calls that, additionally, do **not**
  terminate when `head` fills the 64-byte buffer (a genuine latent bug).
- `src/ui/layout3d.c` — `-Walloc-size-larger-than` on
  `malloc((size_t)n * sizeof(int))` in `compute_call_depth`, where `n` is fed in
  unchecked (a genuine bug: `n` is a clamped search-result count, but nothing in
  the callee enforces the bound).
- `src/pipeline/pass_definitions.c` — `-Walloc-size-larger-than` on
  `calloc((size_t)file_count, ...)` (the `local_cache` and namespace-map `rels`
  allocations) in `cbm_pipeline_pass_definitions`, where the signed `int
  file_count` parameter is fed in unchecked (a negative count casts to an enormous
  `size_t`). A single entry guard refuses a negative `file_count` and fails closed
  with a `{code, message, remediation}` record (`CBM_E_DEFS_FILE_COUNT_RANGE`,
  returning the existing `CBM_NOT_FOUND` status), narrowing the value to
  `[0, INT_MAX]` for both allocations; `file_count == 0` stays a valid no-op. No
  new constant is introduced.

Why these fire despite `GCC_ONLY_FLAGS` (`-Wno-stringop-truncation
-Wno-alloc-size-larger-than`): those suppressions are gated on the `IS_GCC` shell
probe (`$(shell echo | $(CC) -dM -E - | grep …)`), which resolves to `no` in the
native launcher environment, so the prod binaries compile under bare `-Wall
-Wextra -Werror`. The overlays are the robust root-cause fix that does not depend
on that fragile probe.

`apply_ui_werror_patch.py` generates hash-checked, build-local overlays with
**root-cause fixes, not warning suppression**: the two strncpy sites become
`strnlen`-bounded `memcpy` copies with an explicit terminator (identical
truncate-to-buffer semantics, always NUL-terminated), and `compute_call_depth`
gains a `0 < n <= HARD_MAX_NODES` range guard that fails closed with a
`{code, message, remediation}` log record (`CBM_E_LAYOUT_NODE_COUNT_RANGE`) and
leaves the caller's zero-initialized `depth[]` untouched. `HARD_MAX_NODES` is the
file's existing hard node ceiling — no new constant is introduced. `Makefile.cbm`
substitutes the overlays (`PROD_SRCS_UI` / `PROD_SRCS_WITH_ASSETS_UI`) into the
`cbm` / `cbm-with-ui` links; nothing under `vendor/` is written.

Scope note: these overlays reach the **production binaries only**. The same
`layout3d.c` / `watcher.c` sources are also compiled into `libcbm.a`, where the
pre-existing broad `-Wno-*` suppressions (`GCC_ONLY_FLAGS`) mask the diagnostics;
propagating the genuine fixes into the libcbm build (composing with the #227
`watcher.c` spawn overlay) is tracked separately, not done here.

Verify with `python -B scripts/test-cbm-ui-werror-patch.py` (source-hash pins,
persisted overlay-byte readback of each fix, the removed strncpy/unchecked-malloc
idioms, and the drift/empty/unknown-selector fail-closed triad) plus a native
Windows-GNU `make -f patches/cbm/Makefile.cbm cbm-with-ui` that must link
`-Werror`-clean. Temporary integration patch; intended for upstreaming to CBM.

### #229 build-path + vendor-write containment (integration)

The overlays only engage when `cbm-with-ui` is built through **this** patched
`Makefile.cbm` (its `PROD_SRCS_UI` substitution wires the overlays and its
`cbm-with-ui` prerequisites run the generator). `scripts/check-lowered-parity.py`
`build_ui_binary()` therefore builds through `patches/cbm/Makefile.cbm` with an
absolute `BUILD_DIR` (exactly as `build_upstream()` builds `cbm`) — never the
vendored `Makefile.cbm`, which has no overlay substitution and would silently
compile the raw vendored sources.

The UI build must leave the pinned vendor subtree byte-clean. Two generated
outputs otherwise land in `vendor/`:

- `src/ui/embedded_assets.c` — the vendored `scripts/embed-frontend.sh` hard-codes
  this CWD-relative output path. The patched `embed` target runs it from a
  build-local staging root (`$(BUILD_DIR)/astrolabe-ui-embed`) so the file lands
  under `BUILD_DIR`; `PROD_SRCS_WITH_ASSETS_UI` compiles that build-local copy, and
  the recipe fails closed if anything was still written into the vendor subtree.
- `graph-ui/tsconfig.tsbuildinfo` — a **tracked** file rewritten by `tsc -b`. The
  patched `frontend` target runs `npx vite build` instead of `npm run build`
  (= `tsc -b && vite build`); with `noEmit: true`, `tsc -b`'s only artifact is
  that build-info file, and vite bundles `graph-ui/dist` (gitignored) via esbuild
  without consuming tsc output — so the emitted assets are identical and no tracked
  vendor file is touched. (Trade-off: the runtime smoke no longer runs the TS
  typecheck, which stays upstream CBM's dev-flow concern.)

`build_ui_binary()` asserts `git status --porcelain vendor/codebase-memory-mcp` is
empty after the build (`assert_vendor_clean`), failing closed on any drift.
