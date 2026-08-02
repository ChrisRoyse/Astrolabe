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

## Building natively on macOS (Apple Silicon)

ASTROLABE is cross-platform, and its **primary evidence-bearing host is macOS on Apple Silicon**. Build and manual-FSV evidence is produced natively on `aarch64-apple-darwin`, because the Rust host and the static `libcbm.a` archive must share one ABI — here both are arm64 Mach-O. All work runs from `/Users/steveabbey/Documents/Astrolabe`, on `main`, with no launcher and no wrapper script.

Prerequisites and toolchain facts:

- Rust is pinned by `rust-toolchain.toml` (Rust 1.95, edition 2024), host `aarch64-apple-darwin`.
- The C half needs GNU Make and the Xcode Command Line Tools clang (`crates/cbm-sys/build.rs` respects `MAKE`/`CC`/`CXX`/`AR`) plus libclang for bindgen. Install with `xcode-select --install`.
- Build the server:

  ```sh
  cargo build --release -p astrolabe-server
  ```

- For focused pure-Rust iteration, `cargo check -p <crate>` is fast. Anything touching `cbm-sys` also compiles `libcbm.a` through `patches/cbm/Makefile.cbm`.
- `cbm-sys` bindings are **committed per target** (`src/bindings_macos.rs`, `src/bindings.rs`): clang and MSVC disagree on the underlying type of an unsigned C enum, so bindings cannot be shared across hosts. Regenerate the macOS bindings only when the C headers change, and commit the result.
- Apple Silicon note: `-fvisibility=hidden` hides the entire `cbm_*` API on Mach-O, and Apple's `ld64` has no `@file` response-file syntax. Both are handled in `patches/cbm/Makefile.cbm`; see #900.
- GPU: the Forge **Metal** backend (`calyx/crates/calyx-forge/src/metal/`) is the Apple Silicon path, behind the opt-in `metal` feature. It is never substituted automatically — GPU reductions accumulate in tree order, so a vault written with Metal will not byte-match one written with the CPU backend.

**`target/` is disposable.** It is multi-gigabyte scratch, never persistent state. Build, promote the binary you intend to exercise out of `target/`, capture the FSV readback, then `rm -rf target/` and verify absence.

Windows and Linux remain supported targets and their platform branches stay in the tree, but they no longer gate any DoD.

## Manual Full State Verification

Astrolabe uses no test suite, aggregate gate, or CI/CD. Verification is a manual comparison with reality, performed natively on macOS / Apple Silicon and recorded on the driving GitHub issue:

1. Define the source of truth for the behavior: persisted database rows, graph bytes, files, process state, or another physical result.
2. Build and exercise the real artifact against real data. Synthetic inputs are useful when their exact expected outputs are known; they are real inputs, not mocks.
3. Independently read the source of truth after execution instead of trusting a command's return value or response echo.
4. Manually exercise the happy path and at least three relevant boundaries, recording before/after state for each.
5. Record the native command, commit SHA, artifact hash, execution context, and physical readback on the issue. A failure or unavailable observation is explicit evidence of a gap, never a pass.

For an artifact that must run after `target/` is deleted, promote it out of `target/release/` to its install location first (`~/.astrolabe/bin/`), record its SHA-256 alongside the commit SHA of the built tree, and exercise that promoted copy. Never execute closure evidence directly from disposable `target/`.

> **Apple Silicon: promote by atomic rename, never `cp` over a live path.**
> Every arm64 binary must carry a valid code signature (cargo's linker applies an
> ad-hoc one), and macOS caches signature validation **per inode**. Writing new
> bytes into an existing inode that a running process has mapped invalidates that
> cache, and the kernel then kills the process with
> `SIGKILL (Code Signature Invalid)` / `CODESIGNING: Taskgated Invalid Signature`.
> `cp` overwrites in place and hits exactly this. Write a new inode and rename it
> over instead:
>
> ```sh
> cp target/release/astrolabe ~/.astrolabe/bin/.astrolabe.new
> mv -f ~/.astrolabe/bin/.astrolabe.new ~/.astrolabe/bin/astrolabe   # atomic
> codesign -v ~/.astrolabe/bin/astrolabe && ~/.astrolabe/bin/astrolabe --version
> ```
>
> `rename(2)` swaps the directory entry and leaves the old inode intact for
> already-running processes, so nothing is killed mid-flight. Exit code 137
> (128+9) from a freshly promoted binary is this bug, not a crash in the program.

The complete Rust formatting inspection is:

```sh
cargo fmt --all -- --check
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
