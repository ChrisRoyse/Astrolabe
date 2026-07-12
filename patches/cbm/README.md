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
