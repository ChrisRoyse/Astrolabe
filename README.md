# ASTROLABE

ASTROLABE is a coding MCP server for AI agents that fuses two parents into one native binary: **codebase-memory-mcp** (C; tree-sitter + hybrid-LSP code-graph extraction across 158 languages, owned first-class source at `cbm/`, linked in as `libcbm.a`) and **Calyx** (Rust; association-native database engine with measured-bits assay, kernel distillation, conformal guard, oracle, hash-chained provenance, and reversible self-optimization, owned first-class source at `calyx/`). CBM turns a repository into atoms and associations; Calyx turns atoms and associations into grounded intelligence — context packs, guard verdicts, impact predictions, and provenance an agent can trust.

## Read these first

| Document | Role |
|---|---|
| [`CLAUDE.md`](CLAUDE.md) | **Agent operating manual** — mandatory workflow, execution boundary, hygiene rules |
| [`AGENTS.md`](AGENTS.md) | Condensed agent context (same rules, short form) |
| [`docs/astrolabe-blueprint.md`](docs/astrolabe-blueprint.md) | Plan of record — the 23-part design (vision, capability catalog, phases P0–P10) |
| [`docs/BUILDING_ON_CALYX.md`](docs/BUILDING_ON_CALYX.md) | Binding upstream doctrine — the Calyx builder's handbook the blueprint derives from |
| [EPIC #65](https://github.com/ChrisRoyse/Astrolabe/issues/65) | Master build tracker — dependency spine, phase gates, `ASTROLABE_DONE` predicate |
| [#139](https://github.com/ChrisRoyse/Astrolabe/issues/139) | Agent protocol — **GitHub issues are the single source of truth for project state** |

The blueprint records *design*; it never records *progress*. All state — done, in progress, remaining — lives on GitHub issues.

## Repository layout

- `crates/astrolabe-domain` — identity spine (canonical input bytes, `CxId`/series).
- `crates/astrolabe-ingest` — CBM SQLite → vault import, series registry, graph projections, ledger verify.
- `crates/astrolabe-lower` — vault → schema-exact lowered SQLite, team artifact.
- `crates/astrolabe-panel` — the code lens panel (deterministic encoders S0–S17/S21, embedding lenses S18–S20/S22).
- `crates/astrolabe-weave` — similarity graphs, cross-terms, agreement graph, reactive triggers, anomalies.
- `crates/astrolabe-kernel` — kernel/search-scale planning, bridges, label propagation, skills.
- `crates/astrolabe-guard`, `astrolabe-oracle`, `astrolabe-assay`, `astrolabe-anchors`, `astrolabe-provenance` — contract crates brought live per phase (see EPIC #65 for which are live).
- `crates/cbm-sys` + `crates/astrolabe-bridge` — FFI to `libcbm.a` (bindgen bindings; safe wrappers, watcher, tool runner).
- `crates/astrolabe-server` — the MCP surface (wraps the CBM tool runner, adds Astrolabe-native tools).
- `calyx/`, `cbm/` — the two parent trees, now owned first-class source (EPIC #286): edit them directly like any other code in this repo. No pins, no patch overlays, no upstream tracking.
- `patches/cbm/` — Astrolabe-owned libcbm build glue (`Makefile.cbm` + the `ASTRO_*` translation units) compiled directly by `crates/cbm-sys/build.rs`. Not a patch-overlay directory (that machinery was dismantled in #286).

## Building natively on Windows

Build and test evidence is produced with the native Windows GNU toolchain, because the Rust host and the static `libcbm.a` archive must share one ABI. All work runs from `C:\code\Astrolabe` with native Windows executables; for POSIX scripts use a Git for Windows bash (`C:\Program Files\Git\bin\bash.exe`) so the toolchain stays consistent. WSL may be installed and running on the machine — that is fine; project tooling does not detect, block on, or modify it.

Prerequisites and toolchain facts:

- Rust is pinned by `rust-toolchain.toml` (Rust 1.95, edition 2024) with the **`x86_64-pc-windows-gnu` host** — the C half is a static MinGW archive, so Rust and `libcbm.a` must share one ABI. The default MSVC host toolchain cannot perform that link.
- The C half needs GNU Make and a C/C++ toolchain (`crates/cbm-sys/build.rs` respects `MAKE`/`CC`/`CXX`/`AR`) plus libclang for bindgen. A bare `cargo check --workspace` on a default Windows shell fails at `cbm-sys` with "program not found" until these exist.
- Bootstrap everything pinned (Rust-CI-compatible GCC 14.1 bundle, LLVM 20.1 analysis bundle, Cppcheck 2.20.0 source build) with:

  ```powershell
  powershell -ExecutionPolicy Bypass -File scripts\windows-gnu-toolchain.ps1 -Bootstrap
  ```

- Run every native Cargo or aggregate command **through the launcher** so it selects the matching runtime and pinned lint tools, confines child `TEMP`/`TMP`/`TMPDIR` to a launcher-owned `.tmp` child inside the workspace, and removes that child and `target/` on exit. Aggregate evidence must stream directly through the repository wrapper, which creates no log file and must not be wrapped in `Tee-Object` or redirected to a host-side file:

  ```powershell
  .\scripts\invoke-native-aggregate.ps1 -Gate full -UnboundedWorkspaceTests
  ```

- DLL search order matters: the MinGW `bin` directory must precede the Rust GNU host `bin` on `PATH` so `libstdc++-6.dll` loads its matching `libgcc_s_seh-1.dll`. The launcher arranges this; that is one reason not to bypass it.
- Pure-Rust iteration: `cargo check -p <crate> --all-targets` is fast and does not need the C toolchain; anything touching `cbm-sys` does.

## Verification

- `scripts/check.sh` — portable aggregate (all portable gates; emits the named `SKIP[ASTRO_EGRESS_LINUX_REQUIRED]` for the one Linux/strace probe — a recorded coverage gap tracked in [#224](https://github.com/ChrisRoyse/Astrolabe/issues/224), closable by a manual Linux-host run, never pass evidence).
- `scripts/check-full.sh` — complete local gate. It bounds the workspace-test phase by default; exit `125` with `DEFERRED[ASTRO_NATIVE_AGGREGATE]` means downstream suites did not run and is **not** passing evidence. Use the printed `ASTROLABE_WORKSPACE_TEST_TIMEOUT_SECS=0` continuation for an intentional full run.
- `scripts/check-release.sh` — full release gate (binary size + `ASTROLABE_DONE` predicate).
- Formatter: `python scripts/native-cargo-fmt.py --all -- --check`. Do **not** run bare `cargo fmt --all` on Windows — upstream cargo-fmt builds one command line beyond the OS limit on this workspace graph.
- CBM lint: `scripts/ci-cbm-lint.sh` (historical filename; it is a local gate — on non-Linux hosts clang-tidy is skipped by name as a tracked coverage gap; cppcheck/format/NOLINT gates still run).
- **There is no CI/CD.** GitHub Actions is banned in this repository (owner directive, 2026-07-11): no workflows, no required checks, no hosted pipelines. All verification is local full-state verification — the scripts above, run natively, with evidence recorded on the closing GitHub issue. The `ci/` directory holds local gate configs consumed by the check scripts; the name is historical, and nothing in it is GitHub configuration ([#224](https://github.com/ChrisRoyse/Astrolabe/issues/224)).

Platform-limited gates are skipped **by name** (`SKIP[...]`/`INFO[...]` markers), never silently; a named skip is a recorded, issue-tracked coverage gap — not local pass evidence.

## Hygiene invariants (enforced by the workflow)

- `target/` is disposable evidence workspace: every build/test/check batch deletes `C:\code\Astrolabe\target` immediately after evidence capture — including on failure — and verifies it absent before any pause, issue close, or handoff.
- Repository-controlled outputs stay under `C:\code\Astrolabe` (normally `target/`) and are never committed.
- Every commit message body references its issue (`Refs #N` / `Closes #N`).
- Standing invariants for every PR (the HONEST conjunct — trust/freshness/provenance labels, no silent fallback, no unmeasured constants, FSV byte-readback tests, fail-closed `{code, message, remediation}` errors) are listed in `CLAUDE.md` and EPIC #65.
