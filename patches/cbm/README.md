# CBM build integration (`patches/cbm`)

This directory holds the Astrolabe build glue for the owned CBM subsystem
(`cbm/`). The historical "patch overlay" machinery is
**gone** (issue #286): the two parent codebases are now this project's own
first-class source, edited in place, not vendored-and-overlaid.

## What lives here

- **`Makefile.cbm`** — the native build recipe for `libcbm.a` (linked into
  `astrolabe-server` via `crates/cbm-sys`) and the standalone `cbm` /
  `cbm-with-ui` production binaries used by the dual-path parity gates.
- **Astrolabe-owned translation units** compiled into `libcbm.a`:
  - `env_store_config.{c,h}` — explicit FFI store configuration
    (`cbm_astro_set_cache_dir`) plus the fail-closed environment fault record
    (#240/#241). Called from the CBM resolvers under `ASTRO_ENV_STORE`.
  - `astro_spawn.{c,h}` — the shell-free git spawn helper `cbm_spawn_capture`
    (`CreateProcessW` / `posix_spawnp`, no `cmd.exe`) (#227/#228). Called from
    the CBM git shell-out sites under `ASTRO_SPAWN`.
  - `astro_alloc_shim.c` — mimalloc binding shim.
  - `astro_layout_probe.c` — native C ABI layout probe for the FFI bindings.

## The overlays are now compile-time features of the owned sources (#286)

Every former `patches/cbm` overlay is a plain edit in the owned CBM source,
guarded by an `ASTRO_*` macro so each build artifact selects the exact behavior
it had before the overlay machinery was dissolved. The Makefile defines the
flags per artifact:

| Feature (issue)                    | Guard macro          | libcbm.a | `cbm`/`cbm-with-ui` | test-runner |
| ---------------------------------- | -------------------- | :------: | :-----------------: | :---------: |
| store resolution (#240/#241)       | `ASTRO_ENV_STORE`    |    ✓     |          —          |      —      |
| shell-free git spawn (#227)        | `ASTRO_SPAWN`        |    ✓     |          —          |      —      |
| shell-arg validator (#228)         | `ASTRO_SHELLARG`     |    ✓     |          —          |      —      |
| pressure-log buffers (#149)        | `ASTRO_MEM_PRESSURE` |    ✓     |          —          |      —      |
| worker-failure diagnostics (#282)  | `ASTRO_WORKER_DIAG`  |    ✓     |          ✓          |      —      |
| `-Werror` root-cause fixes (#229/#273) | _(unconditional)_ |    ✓     |          ✓          |      ✓      |

- `libcbm` defines the first five via `LIBCBM_ASTRO_DEFS` (in `LIBCBM_CFLAGS`).
- the production binaries define `ASTRO_PROD_DEFS` (`ASTRO_WORKER_DIAG`).
- the C test-runner defines none — the plain vendored behavior.
- the #229 `-Werror` root-cause fixes are **no longer macro-gated** (#273): the
  unchecked alloc-size guards (`ui/layout3d.c`, `pipeline/pass_definitions.c`) and
  the non-terminating-`strncpy` fixes (`watcher/watcher.c`, `pipeline/pass_envscan.c`)
  are unconditional in the owned source, so they ship in every artifact. The
  blanket `-Wno-stringop-truncation` / `-Wno-alloc-size-larger-than` that used to
  mask them on the unguarded (libcbm.a, test-runner) paths were removed from
  `GCC_ONLY_FLAGS`, keeping both diagnostics on as `-Werror` everywhere.

This per-artifact matrix is verified by Full State Verification (FSV), not a gate
script: build each artifact natively (`cargo build --release`, which drives this
Makefile through `crates/cbm-sys/build.rs`) and read back the compiled behavior — for
example, confirm a guarded symbol is present only in the artifacts whose
`-DASTRO_*` flag the Makefile passes (`nm`/disassembly of `libcbm.a` vs the
production binaries). The former `scripts/test-cbm-overlay-sources.py` gate was
deleted with the rest of the aggregate gate/check suite under the 2026-07-13
FSV-only directive (d90100d) and is not to be rebuilt.

## Changing CBM code

It is normal owned source: edit the `.c`/`.h` under
`cbm/` directly, and add or adjust an `ASTRO_*` guard only
when a change must NOT reach every artifact. Verify a new guarded behavior by FSV
— build the affected artifacts and read back that the behavior appears only under
its flag — not with any gate script. There is no pin file, no applier, and no
hash-checked overlay to regenerate.
