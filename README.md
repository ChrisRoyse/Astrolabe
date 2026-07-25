# ASTROLABE

ASTROLABE is a coding MCP server for AI agents that fuses two parents into one native binary: **codebase-memory-mcp** (C; tree-sitter + hybrid-LSP code-graph extraction across 158 languages, owned first-class source at `cbm/`, linked in as `libcbm.a`) and **Calyx** (Rust; association-native database engine with measured-bits assay, kernel distillation, conformal guard, oracle, hash-chained provenance, and reversible self-optimization, owned first-class source at `calyx/`). CBM turns a repository into atoms and associations; Calyx turns atoms and associations into grounded intelligence — context packs, guard verdicts, impact predictions, and provenance an agent can trust.

## Read these first

| Document | Role |
|---|---|
| [`CLAUDE.md`](CLAUDE.md) | **Agent operating manual** — mandatory workflow, execution boundary, hygiene rules |
| [`AGENTS.md`](AGENTS.md) | Condensed agent context (same rules, short form) |
| [`docs/astrolabe-blueprint.md`](docs/astrolabe-blueprint.md) | Plan of record — the 23-part design (vision, capability catalog, phases P0–P10) |
| [`docs/BUILDING_ON_CALYX.md`](docs/BUILDING_ON_CALYX.md) | Binding upstream doctrine — the Calyx builder's handbook the blueprint derives from |
| [EPIC #65](https://github.com/ChrisRoyse/Astrolabe/issues/65) | Master build tracker — dependency spine, phase completion criteria, `ASTROLABE_DONE` predicate |
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

Build and manual-FSV evidence is produced with the native Windows GNU toolchain, because the Rust host and the static `libcbm.a` archive must share one ABI. All work runs from `C:\code\Astrolabe` with native Windows executables; for POSIX scripts use a Git for Windows bash (`C:\Program Files\Git\bin\bash.exe`) so the toolchain stays consistent. WSL may be installed and running on the machine — that is fine; project tooling does not detect, block on, or modify it.

Prerequisites and toolchain facts:

- Rust is pinned by `rust-toolchain.toml` (Rust 1.95, edition 2024) with the **`x86_64-pc-windows-gnu` host** — the C half is a static MinGW archive, so Rust and `libcbm.a` must share one ABI. The default MSVC host toolchain cannot perform that link.
- The C half needs GNU Make and a C/C++ toolchain (`crates/cbm-sys/build.rs` respects `MAKE`/`CC`/`CXX`/`AR`) plus libclang for bindgen. A bare `cargo check --workspace` on a default Windows shell fails at `cbm-sys` with "program not found" until these exist.
- Bootstrap everything pinned (Rust-CI-compatible GCC 14.1 bundle, LLVM 20.1 analysis bundle, Cppcheck 2.20.0 source build) with:

  ```powershell
  powershell -ExecutionPolicy Bypass -File scripts\windows-gnu-toolchain.ps1 -Issue <driving-issue> -Bootstrap
  ```

- Claim and re-read the driving GitHub issue before launching. Run every native Cargo or C build command **through the launcher** so it selects the matching runtime and pinned analysis tools, confines child `TEMP`/`TMP`/`TMPDIR` to a launcher-owned workspace child, and lets the exact live owner remove its generation and `target/` on exit. A single command is passed as JSON:

  ```powershell
  $toolArgs = '["check", "--workspace"]'
  .\scripts\windows-gnu-toolchain.ps1 -Issue <driving-issue> -Command cargo -CommandArgsJson $toolArgs
  ```

  A contiguous check/build batch is one nested JSON plan owned by one launcher generation:

  ```powershell
  $batch = '[["cargo", "check", "--workspace"], ["cargo", "build", "--workspace"]]'
  .\scripts\windows-gnu-toolchain.ps1 -Issue <driving-issue> -BatchCommandsJson $batch
  ```

- DLL search order matters: the MinGW `bin` directory must precede the Rust GNU host `bin` on `PATH` so `libstdc++-6.dll` loads its matching `libgcc_s_seh-1.dll`. The launcher arranges this; that is one reason not to bypass it.
- For focused pure-Rust iteration, pass `check -p <crate> --all-targets` through the same launcher. Anything touching `cbm-sys` also exercises the pinned C toolchain.

## Manual Full State Verification

Astrolabe uses no test suite, aggregate gate, or CI/CD. Verification is a manual comparison with reality, performed natively on Windows and recorded on the driving GitHub issue:

1. Define the source of truth for the behavior: persisted database rows, graph bytes, files, process state, or another physical result.
2. Build and exercise the real artifact against real data. Synthetic inputs are useful when their exact expected outputs are known; they are real inputs, not mocks.
3. Independently read the source of truth after execution instead of trusting a command's return value or response echo.
4. Manually exercise the happy path and at least three relevant boundaries, recording before/after state for each.
5. Record the native command, commit SHA, artifact hash, execution context, and physical readback on the issue. A failure or unavailable observation is explicit evidence of a gap, never a pass.

For an artifact that must run after Cargo output cleanup, stage it during the same issue-owned launcher lease with `scripts\native-fsv-artifact.ps1`, and execute/read it only through `scripts\native-fsv-run.ps1`. Follow the exact lifecycle in `CLAUDE.md`; never execute closure evidence directly from disposable `target/`.

The complete Rust formatting inspection is:

```powershell
python scripts/native-cargo-fmt.py --all -- --check
```

Do not run bare `cargo fmt --all` on native Windows: upstream cargo-fmt builds one command line beyond the Windows limit for this workspace graph.

For a non-build inspection, remain read-only and run:

```powershell
Set-Location C:\code\Astrolabe
git status --short --branch
Get-Content -LiteralPath CLAUDE.md -Raw
gh issue view <driving-issue> --comments
Test-Path -LiteralPath .tmp\astrolabe-launcher.lock
Test-Path -LiteralPath target
```

The final two reads report physical namespace state only; they never authorize deletion. Preserve any non-absent launcher or target state and follow the issue-bound ownership/recovery procedure in `CLAUDE.md`.

## Hygiene invariants (enforced by the workflow)

- `target/` is disposable evidence workspace: the exact live launcher owner removes `C:\code\Astrolabe\target` immediately after every build/manual-verification batch — including on failure — and its absence is independently read back before any pause, issue close, or handoff.
- Repository-controlled outputs stay under `C:\code\Astrolabe` (normally `target/`) and are never committed.
- Every commit message body references its issue (`Refs #N` / `Closes #N`).
- Standing invariants for every change (the HONEST conjunct — trust/freshness/provenance labels, no silent fallback, no unmeasured constants, independent FSV byte readback, fail-closed `{code, message, remediation}` errors) are listed in `CLAUDE.md` and EPIC #65.
