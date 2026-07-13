# CBM Cache-Path Construction Sites (pinned)

The CBM project store has no registry table: a project is "registered" purely by
the presence of `<slug>.db` in the resolved cache directory. The library resolves
that directory in exactly one place —
`vendor/codebase-memory-mcp/src/foundation/platform.c :: cbm_resolve_cache_dir()`
— which honours `CBM_CACHE_DIR` and otherwise falls back to
`$HOME/.cache/codebase-memory-mcp`.

The vendored **tests do not call it**. They rebuild the same formula by hand from
`getenv("HOME")`. That duplication is the root cause of #194/#232: a
`CBM_CACHE_DIR` redirect moves the library's *write* path but not the tests'
*read* path, which is why the redirect regressed ~808 tests (de2fc30) and why the
store leaks fixture registrations into the operator's profile when it is not
redirected. Astrolabe's fix is to redirect `HOME` — the one input **both** halves
read — for the CBM test phase (`scripts/ci-cbm-test.sh`), so the two halves move
together.

`vendor/codebase-memory-mcp` is now owned first-class source (#286). Collapsing
the duplication (a single `th_cache_dir()` accessor in `tests/test_helpers.h`
delegating to `cbm_resolve_cache_dir()`) is a normal code change tracked
separately; what this manifest enforces is that it never **grows**:
`scripts/check-cbm-cache-paths.py` recomputes every construction site under the
pinned tree and requires an exact match. A new hand-built cache path or a new
`getenv("HOME")` fixture site fails the CBM lint gate closed. Astrolabe-owned C
under `patches/cbm/` is banned from the pattern outright.

Counts are raw occurrences (including comments and doc headers) of the literal
`.cache/codebase-memory-mcp` and of `getenv("HOME")` / `getenv("USERPROFILE")`.
Measured at CBM pin `49358971c30820dac674b8e036877e3b6c0ff172`. Re-derive with
`python scripts/check-cbm-cache-paths.py --print-baseline` whenever the pin moves,
and review the delta — a shrinking count means upstream adopted the resolver.

Shell harnesses under the pinned tree are scanned for the same reason: they too
rebuild `$HOME/.cache/codebase-memory-mcp` by hand (`tests/test_cpp_index_hang.sh`,
`tests/smoke_guard.sh`), so a `CBM_CACHE_DIR` redirect would have split them from
the library exactly like the C tests, while a `HOME` redirect moves them with it.
A grep gate cannot see a subprocess anyway — the byte-manifest guard in
`scripts/check-cbm-cache-hermeticity.py` is what actually proves the store came
out untouched.

| File | `.cache/codebase-memory-mcp` literals | `getenv("HOME"/"USERPROFILE")` sites | Note |
|---|---:|---:|---|
| `scripts/setup.sh` | 1 | 0 | Installer message naming the default store. |
| `scripts/smoke-test.sh` | 1 | 0 | Smoke harness; sets `CBM_CACHE_DIR` for its dry run. |
| `scripts/test-shards.sh` | 1 | 0 | #280 sharded-suite containment: pre-creates the store dir under each shard's already-redirected `$shard_home` sandbox so vendored tests land in the sandbox, not the operator store. Moves with `HOME` exactly like the resolver; the byte-manifest hermeticity guard proves the real store untouched. |
| `src/cli/cli.h` | 1 | 0 | Doc comment on the cache-listing API. |
| `src/foundation/platform.c` | 2 | 0 | **Sanctioned definition site**: `cbm_resolve_cache_dir()`. Two textual sites since #286 Phase A, but they are the SAME formula in the same resolver: the `#ifdef ASTRO_ENV_STORE` truncation-checked variant (platform.c:498) and its `#else` original (platform.c:504). Still exactly one resolver; no split write/read path. |
| `src/foundation/platform.h` | 1 | 0 | Doc comment on the resolver contract. |
| `src/ui/config.c` | 1 | 0 | Doc comment; the code calls the resolver. |
| `src/ui/config.h` | 1 | 0 | Doc comment; the code calls the resolver. |
| `tests/scale_contract.sh` | 1 | 0 | Shell harness unlinking its own project db from the store. |
| `tests/smoke_guard.sh` | 1 | 0 | Shell harness reading the store directly. |
| `tests/test_cpp_index_hang.sh` | 2 | 0 | Shell harness unlinking its own project db from the store. |
| `tests/repro/repro_harness.h` | 1 | 1 | Hand-built store path + banned `home = "/tmp"` fallback. |
| `tests/repro/repro_issue434.c` | 1 | 1 | Hand-built db path + banned `home = "/tmp"` fallback. |
| `tests/repro/repro_issue521.c` | 1 | 1 | Hand-built store path + banned `home = "/tmp"` fallback. |
| `tests/repro/repro_issue523.c` | 1 | 0 | Comment describing the global store. |
| `tests/test_convergence_probe.c` | 1 | 1 | Hand-built store path. |
| `tests/test_discover.c` | 0 | 1 | Reads `HOME` for a discovery fixture; builds no store path. |
| `tests/test_edge_imports.c` | 1 | 1 | Hand-built store path. |
| `tests/test_edge_structural.c` | 1 | 1 | Hand-built store path. |
| `tests/test_edge_types_probe.c` | 1 | 1 | Hand-built store path. |
| `tests/test_grammar_probe_a.c` | 1 | 1 | Hand-built store path. |
| `tests/test_grammar_probe_b.c` | 1 | 1 | Hand-built store path. |
| `tests/test_grammar_probe_c.c` | 1 | 1 | Hand-built store path. |
| `tests/test_grammar_probe_d.c` | 1 | 1 | Hand-built store path. |
| `tests/test_grammar_probe_e.c` | 1 | 1 | Hand-built store path. |
| `tests/test_grammar_probe_f.c` | 1 | 1 | Hand-built store path. |
| `tests/test_grammar_probe_g.c` | 1 | 1 | Hand-built store path. |
| `tests/test_httpd.c` | 0 | 2 | Saves/restores `HOME` around a redirected fixture. |
| `tests/test_incremental.c` | 2 | 1 | Hand-built db path + store path. |
| `tests/test_index_resilience.c` | 1 | 1 | Hand-built store path. |
| `tests/test_integration.c` | 2 | 1 | Hand-built db path + store path (the `cbm_excl_*` leak site). |
| `tests/test_lang_contract.c` | 1 | 1 | Hand-built store path. |
| `tests/test_lsp_resolution_probe.c` | 1 | 1 | Hand-built store path. |
| `tests/test_matrix_known_classes.c` | 1 | 1 | Hand-built store path. |
| `tests/test_matrix_new_constructs.c` | 1 | 1 | Hand-built store path. |
| `tests/test_node_creation_probe.c` | 1 | 1 | Hand-built store path. |
| `tests/test_ui.c` | 2 | 10 | Redirects `HOME` to its own temp dir before building the path — already hermetic. |
